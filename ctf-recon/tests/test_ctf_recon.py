from argparse import Namespace
from pathlib import Path

import ctf_recon


def test_flag_like_strings_returns_full_unique_matches():
    outputs = {
        "strings": {
            "stdout": "noise flag{this_is_real}\nCTF{SECOND_MATCH}\nflag{this_is_real}",
            "stderr": "",
        }
    }

    assert ctf_recon.flag_like_strings(outputs) == ["flag{this_is_real}", "CTF{SECOND_MATCH}"]


def test_safe_report_stem_handles_urls_and_unsafe_characters():
    assert ctf_recon.safe_report_stem("https://chal.example/path/to?id=1") == "chal.example_path_to"
    assert ctf_recon.safe_report_stem("host:31337") == "host_31337"
    assert ctf_recon.safe_report_stem("../../../weird name?.bin") == "weird_name"


def test_pwn_commands_do_not_execute_binaries_by_default():
    commands = ctf_recon.gather_commands(
        "pwn",
        "challenge.bin",
        is_url_target=False,
        net_mode=False,
        host_port=None,
        magic_desc="ELF 64-bit executable",
    )
    names = [name for name, _cmd, _timeout in commands]

    assert "ltrace" not in names
    assert "strace" not in names


def test_pwn_commands_can_enable_explicit_execution():
    commands = ctf_recon.gather_commands(
        "pwn",
        "challenge.bin",
        is_url_target=False,
        net_mode=False,
        host_port=None,
        magic_desc="ELF 64-bit executable",
        allow_execution=True,
    )
    names = [name for name, _cmd, _timeout in commands]

    assert "ltrace" in names
    assert "strace" in names


def test_process_target_writes_reports_to_output_dir(tmp_path, monkeypatch):
    sample = tmp_path / "note.txt"
    sample.write_text("flag{sample_flag_value}\n", encoding="utf-8")
    out_dir = tmp_path / "reports"
    args = Namespace(
        category="misc",
        json_out=True,
        output_dir=str(out_dir),
        allow_execution=False,
    )

    monkeypatch.setattr(ctf_recon, "guess_magic", lambda _target: "ASCII text")
    monkeypatch.setattr(
        ctf_recon,
        "select_commands_with_llm",
        lambda _category, _target, commands: [("mock_strings", ["mock"], 1)],
    )
    monkeypatch.setattr(
        ctf_recon,
        "run_command",
        lambda _cmd, timeout=1, cwd=None: {"status": "ok", "stdout": "flag{sample_flag_value}", "stderr": ""},
    )
    monkeypatch.setattr(ctf_recon, "call_llm", lambda _prompt: (None, "missing_api_key"))

    result = ctf_recon.process_target(str(sample), args, None, None)

    report_path = Path(result["report_path"])
    assert report_path.parent == out_dir
    assert report_path.exists()
    assert report_path.with_suffix(".json").exists()
    assert result["flag_hits"] == ["flag{sample_flag_value}"]
