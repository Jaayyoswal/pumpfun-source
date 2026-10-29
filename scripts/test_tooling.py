#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import os
import struct
import tempfile
from pathlib import Path
import unittest
from types import SimpleNamespace
import deep_section_analysis
import analyze
from compare import compare
from source_manifest_guard import strict_manifest
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


class SourceManifestLinkedDirectoryTests(unittest.TestCase):
    def crate(self, root):
        root = root.resolve()
        crate = root / 'repo/crate'
        crate.mkdir(parents=True)
        (crate / 'Cargo.toml').write_text('[package]\nname = "probe"\n')
        outside = root / 'outside'
        outside.mkdir()
        (outside / 'lib.rs').write_text('pub fn external() {}\n')
        return crate, outside

    def test_plain_source_directory_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            crate, _ = self.crate(Path(temporary))
            (crate / 'src').mkdir()
            (crate / 'src/lib.rs').write_text('pub fn local() {}\n')
            self.assertEqual(set(strict_manifest(crate, crate, crate.parent)), {'crate/Cargo.toml', 'crate/src/lib.rs'})

    def test_symlinked_source_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            crate, outside = self.crate(Path(temporary))
            os.symlink(outside, crate / 'src')
            with self.assertRaisesRegex(ValueError, 'symlinked directory'):
                strict_manifest(crate, crate, crate.parent)

    def test_symlinked_directory_named_target_below_the_crate_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            crate, outside = self.crate(Path(temporary))
            (crate / 'src').mkdir()
            os.symlink(outside, crate / 'src/target')
            with self.assertRaisesRegex(ValueError, 'symlinked directory'):
                strict_manifest(crate, crate, crate.parent)

    def test_symlinked_directory_in_extra_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            crate, outside = self.crate(Path(temporary))
            assets = crate.parent / 'assets'
            assets.mkdir()
            os.symlink(outside, assets / 'tables')
            with self.assertRaisesRegex(ValueError, 'symlinked directory'):
                strict_manifest(crate, crate, crate.parent, [assets])


if __name__=='__main__': unittest.main()
