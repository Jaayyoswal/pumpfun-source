#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import tempfile
from pathlib import Path
import unittest
from types import SimpleNamespace
import deep_section_analysis
import analyze
from compare import compare
class ComparisonTests(unittest.TestCase):
    def test_equal(self): self.assertTrue(compare(b'abc\0\0',b'abc\0\0')['full_byte_equality'])
    def test_code_mutation(self): self.assertEqual(compare(b'abc\0\0',b'axc\0\0')['first_difference'],1)
    def test_padding_mutation(self): self.assertEqual(compare(b'abc\0\0',b'abc\0x')['first_difference'],4)
    def test_truncated_padding(self): self.assertFalse(compare(b'abc\0\0',b'abc\0')['full_byte_equality'])
    def test_extended_padding(self): self.assertFalse(compare(b'abc\0',b'abc\0\0')['full_byte_equality'])
    def test_empty(self): self.assertEqual(compare(b'a',b'')['first_difference'],0)


class RelocationTargetTests(unittest.TestCase):
    def test_target_section_uses_address_not_file_offset(self):
        blob = bytearray(64)
        struct.pack_into('<QQ', blob, 0, 0x1000, 2)
        elf = SimpleNamespace(
            b=bytes(blob),
            symbols={},
            lo=0x2000,
            hi=0x3000,
            secs={
                '.rel.dyn': (0, 9, 0, 0, 0, 16, 0, 0, 1, 16),
                '.rodata': (0, 1, 2, 0x1000, 0x20, 0x100, 0, 0, 1, 0),
            },
        )
        report = deep_section_analysis.analyze_relocations(elf)
        self.assertEqual(report['entries'][0]['target_section'], '.rodata')


class InstructionLogNameTests(unittest.TestCase):
    def names(self, name):
        blob = (analyze.ROOT / 'evidence/original' / name / 'deployed.so').read_bytes()
        return set(analyze.instruction_log_names(blob, analyze.known_instruction_names(name)))

    def test_idl_names_do_not_absorb_adjacent_text(self):
        pump = self.names('pump')
        self.assertIn('Buy', pump)
        self.assertIn('UpdateBuybackConfig', pump)
        self.assertIn('IdlResizeAccount', pump)
        self.assertNotIn('BuyCreateV2Disabled', pump)
        self.assertNotIn('UpdateBuybackConfigAn', pump)
        self.assertNotIn('IdlResizeAccountdata', pump)

        amm = self.names('pump_amm')
        self.assertIn('ClaimCashback', amm)
        self.assertIn('IdlCreateAccount', amm)
        self.assertNotIn('ClaimCashbacksol', amm)
        self.assertNotIn('IdlCreateAccountanchor', amm)

        fees = self.names('pump_fees')
        self.assertIn('Withdraw', fees)
        self.assertIn('CrankDonationFeePda', fees)
        self.assertNotIn('Withdrawaccountsol', fees)
        self.assertNotIn('CrankDonationFeePdaFee', fees)

    def test_program_names_fall_back_to_captures(self):
        self.assertEqual(
            analyze.program_names(),
            ['pump', 'pump_amm', 'pump_fees', 'mayhem'],
        )

    def test_mayhem_fallback_is_unchanged(self):
        names = self.names('mayhem')
        self.assertEqual(len(names), 25)
        self.assertIn('Buy', names)
        self.assertIn('InitializeGlobalParams', names)


@unittest.skipUnless(sys.version_info >= (3, 11), 'pump_dependency_cache needs tomllib')
class DependencyCacheArchiveTests(unittest.TestCase):
    def import_seed(self, extra=None):
        import pump_dependency_cache as m
        sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            crate = root / 'repo/prog'
            crate.mkdir(parents=True)
            (crate / 'Cargo.toml').write_text('[package]\nname="prog"\nversion="0.1.0"\n[workspace]\n')
            files = {'Cargo.toml': b'[package]\nname="dep"\nversion="1.0.0"\n', 'src/lib.rs': b'pub fn f() {}\n'}
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w:gz') as tar:
                for name, body in files.items():
                    info = tarfile.TarInfo('dep-1.0.0/' + name)
                    info.size = len(body)
                    tar.addfile(info, io.BytesIO(body))
            home = root / 'cargo'
            namespace = 'index.crates.io-1949cf8c6b5b557f'
            archive = home / 'registry/cache' / namespace / 'dep-1.0.0.crate'
            archive.parent.mkdir(parents=True)
            archive.write_bytes(data.getvalue())
            (crate / 'Cargo.lock').write_text(
                'version = 3\n[[package]]\nname="dep"\nversion="1.0.0"\nchecksum="%s"\n'
                '[[package]]\nname="prog"\nversion="0.1.0"\n' % sha(archive))
            source = home / 'registry/src' / namespace / 'dep-1.0.0'
            for name, body in {**files, '.cargo-ok': b'{"v":1}', **({extra: b'fn main() {}\n'} if extra and extra != 'linked' else {})}.items():
                (source / name).parent.mkdir(parents=True, exist_ok=True)
                (source / name).write_bytes(body)
            if extra == 'linked':
                os.symlink(source / 'src', source / 'linked')
            build = root / 'build'
            (build / 'target/release/deps').mkdir(parents=True)
            (build / 'target/release/deps/libdep-0123456789abcdef.rlib').write_bytes(b'rlib')
            for name in ['candidate.so', 'unstripped.so']:
                (build / name).write_bytes(name.encode())
            wrapper = root / 'wrapper'
            wrapper.write_text('w')
            (build / 'build-comparison.json').write_text(json.dumps({
                'returncode': 0, 'source_unchanged': True, 'source_sha256': {},
                'comparison': {'candidate_sha256': sha(build / 'candidate.so')},
                'unstripped_sha256': sha(build / 'unstripped.so'),
                'tool_sha256': {'rustc': 'r', 'cargo': 'c'}, 'source_wrapper_sha256': sha(wrapper),
                'environment': {'CARGO_HOME': str(home)},
                'command': ['cargo', '--manifest-path', str(crate / 'Cargo.toml')]}))
            cache = object.__new__(m.DependencyCache)
            cache.repo, cache.crate, cache.workspace, cache.direct = root / 'repo', crate, crate, False
            cache.env = {'CARGO_HOME': str(home)}
            cache.target = 'sbf-solana-solana'
            cache.target_flags_key = 'CARGO_TARGET_SBF_SOLANA_SOLANA_RUSTFLAGS'
            cache.tools = {'rust/bin/rustc': 'r', 'rust/bin/cargo': 'c'}
            cache.sources = {str(source): m.tree(source)}
            cache.packages = cache.crates = {'dep'}
            cache.main_names = {'prog'}
            cache.context = {'wrapper_sha256': sha(wrapper), 'external_sources': cache.sources}
            cache.root, cache.key, cache.record = root / 'cache', 'k', {}
            cache.entry = cache.root / 'k'
            try:
                cache.import_clean_build(build)
            finally:
                published = cache.entry.exists()
            return cache.record, published

    def test_locked_source_tree_is_imported(self):
        record, published = self.import_seed()
        self.assertEqual(record['imported_clean_build']['archive_files_verified'], 2)
        self.assertTrue(published)

    def test_files_absent_from_locked_archive_are_rejected(self):
        for extra in ['build.rs', 'src/evil.rs', 'linked']:
            with self.subTest(extra=extra), self.assertRaisesRegex(AssertionError, 'absent from locked archive'):
                self.import_seed(extra)


if __name__=='__main__': unittest.main()
