"""MISP JSON import into `ioc` watchlists (`forense intel misp`)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forense.cli import EXIT_ERROR, EXIT_OK, main
from forense.core.errors import ForenseError
from forense.core.intel import MispImport, import_misp, import_opencti, write_watchlist
from forense.modules import get_module
from forense.modules.base import ResultSink
from forense.modules.generic.ioc import load_watchlist


def _attr(kind: str, value: str, deleted: bool = False) -> dict:
    return {"type": kind, "value": value, "deleted": deleted}


def _event(uuid: str = "e1", info: str = "Phishing kit", attributes: tuple = ()) -> dict:
    return {"uuid": uuid, "info": info, "date": "2026-10-20", "Attribute": list(attributes)}


def run(module: str, target: Path, tmp_path: Path, **options):
    sink = ResultSink()
    ctx = get_module(module).run(target, tmp_path / f"out_{module}", options, sink=sink)
    return ctx, sink


def test_every_ioc_type_is_mapped(tmp_path):
    source = tmp_path / "event.json"
    source.write_text(json.dumps({"Event": _event(attributes=(
        _attr("sha256", "A" * 64),
        _attr("md5", "c" * 32),
        _attr("ip-dst|port", "203.0.113.9|443"),
        _attr("domain", "EVIL.example"),
        _attr("hostname|ip", "cdn.evil.example|198.51.100.7"),
        _attr("url", "http://evil.example/payload"),
        _attr("email-src", "phish@evil.example"),
        _attr("filename|md5", "invoice.exe|" + "b" * 32),
        _attr("regkey", r"HKCU\Software\Evil"),
        _attr("user-agent", "EvilBot/1.0"),
        _attr("comment", "not an indicator"),
        _attr("sha1", "d" * 40, deleted=True),  # deleted attributes are never imported
    ))}), encoding="utf-8")

    result = import_misp(source)
    assert result.events == 1 and result.attributes == 12 and result.used == 10
    assert result.duplicates == 0
    assert result.skipped == {"comment": 1}
    assert set(result.indicators) == {
        "a" * 64, "c" * 32, "203.0.113.9", "EVIL.example", "cdn.evil.example", "198.51.100.7",
        "http://evil.example/payload", "phish@evil.example", "b" * 32, r"HKCU\Software\Evil",
        "EvilBot/1.0"}
    assert result.notes == ["misp: e1 | Phishing kit | 2026-10-20"]

    out = write_watchlist(result, tmp_path / "watchlist.txt")
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("# Forense watchlist generated from a MISP export")
    assert "# misp: e1 | Phishing kit | 2026-10-20" in lines
    body = [line for line in lines if not line.startswith("#")]
    assert body == sorted(result.indicators)
    # the file is a plain watchlist: comments out, indicators in, matching is case-insensitive
    assert load_watchlist(out) == {i.lower() for i in result.indicators}


def test_all_export_shapes_and_cross_event_dedup(tmp_path):
    first = _event("e1", "Kit A", (_attr("domain", "evil.example"), _attr("ip-src", "203.0.113.5")))
    second = _event("e2", "Kit B", (_attr("domain", "EVIL.example"), _attr("sha256", "a" * 64)))
    expected = {"evil.example", "203.0.113.5", "a" * 64}

    for payload in ({"response": [{"Event": first}, {"Event": second}]},
                    [{"Event": first}, {"Event": second}]):
        source = tmp_path / "export.json"
        source.write_text(json.dumps(payload), encoding="utf-8")
        result = import_misp(source)
        assert set(result.indicators) == expected
        assert result.duplicates == 1  # the same domain (any case) twice
        assert result.notes == ["misp: e1 | Kit A | 2026-10-20", "misp: e2 | Kit B | 2026-10-20"]

    single = tmp_path / "single.json"
    single.write_text(json.dumps({"Event": _event("e3", "One", (_attr("md5", "b" * 32),))}), encoding="utf-8")
    assert import_misp(single).indicators == ["b" * 32]

    event_list_value = tmp_path / "list-value.json"
    event_list_value.write_text(json.dumps({"Event": [first]}), encoding="utf-8")
    assert import_misp(event_list_value).events == 1


def test_broken_inputs_are_rejected_without_output(tmp_path, monkeypatch):
    missing = tmp_path / "nope.json"
    with pytest.raises(ForenseError) as exc:
        import_misp(missing)
    assert exc.value.code == "error.intel_input_missing"

    broken = tmp_path / "broken.json"
    broken.write_text('{"Event": {"uuid": "x", "Attribute": [', encoding="utf-8")
    with pytest.raises(ForenseError) as exc:
        import_misp(broken)
    assert exc.value.code == "error.intel_misp_invalid"

    for payload in ({"Other": 1}, '"just a string"', [{"Event": None}], {"response": "not a list"}):
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ForenseError) as exc:
            import_misp(bad)
        assert exc.value.code == "error.intel_misp_invalid"

    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"Event": _event(attributes=(_attr("comment", "no"),))}), encoding="utf-8")
    with pytest.raises(ForenseError) as exc:
        import_misp(empty)
    assert exc.value.code == "error.intel_misp_empty"

    big = tmp_path / "big.json"
    big.write_text('{"a": 123456}', encoding="utf-8")  # 13 bytes, beyond the patched 4-byte limit
    monkeypatch.setattr("forense.core.intel.MAX_INTEL_BYTES", 4)
    with pytest.raises(ForenseError) as exc:
        import_misp(big)
    assert exc.value.code == "error.intel_misp_too_large"
    assert not (tmp_path / "big.watchlist.txt").exists()


def test_cli_intel_misp(tmp_path, capsys):
    source = tmp_path / "export.json"
    source.write_text(json.dumps({"Event": _event("e1", "Kit", (_attr("domain", "evil.example"),))}),
                      encoding="utf-8")
    out = tmp_path / "custom.txt"
    assert main(["intel", "misp", str(source), "-o", str(out)]) == EXIT_OK
    message = capsys.readouterr().out
    assert "Watchlist written" in message and str(out) in message and "evil.example" not in message
    assert out.is_file() and not out.read_text().startswith("{")

    # default output name: EXPORT.watchlist.txt next to the export
    assert main(["-L", "es", "inteligencia", "misp", str(source)]) == EXIT_OK
    text = capsys.readouterr().out
    assert "Lista de vigilancia creada" in text
    assert (tmp_path / "export.watchlist.txt").is_file()

    # the output cannot silently replace the source export
    assert main(["intel", "misp", str(source), "-o", str(source)]) == EXIT_ERROR
    assert "itself" in capsys.readouterr().err
    assert json.loads(source.read_text(encoding="utf-8"))["Event"]["uuid"] == "e1"

    # a broken export is a localized error, not a traceback
    broken = tmp_path / "broken.json"
    broken.write_text("not json", encoding="utf-8")
    assert main(["intel", "misp", str(broken), "-o", str(tmp_path / "x.txt")]) == EXIT_ERROR
    assert "not a valid MISP JSON export" in capsys.readouterr().err
    assert main(["-L", "es", "intel", "misp", str(tmp_path / "nope.json"), "-o", str(tmp_path / "y.txt")]) == EXIT_ERROR
    assert "No se encuentra la exportación" in capsys.readouterr().err


def test_misp_watchlist_drives_ioc_findings(tmp_path):
    """The import is only useful if the result feeds the module it was made for."""
    evidence = tmp_path / "drop"
    evidence.mkdir()
    (evidence / "note.txt").write_text("contact cdn.evil.example for the payload\n", encoding="utf-8")
    (evidence / "clean.txt").write_text("nothing to see here\n", encoding="utf-8")
    source = tmp_path / "misp.json"
    source.write_text(json.dumps({"Event": _event("e9", "Kit", (
        _attr("hostname", "cdn.evil.example"), _attr("sha256", "f" * 64),
    ))}), encoding="utf-8")
    result = import_misp(source)
    watchlist = write_watchlist(result, tmp_path / "watchlist.txt")

    ctx, sink = run("ioc", evidence, tmp_path, watchlist=str(watchlist))
    hits = [f for f in sink.findings if f["code"] == "ioc.watchlist_match"]
    assert [(f["params"]["indicator"], f["params"]["file"]) for f in hits] == \
        [("cdn.evil.example", "note.txt")]
    assert ctx.summary["watchlist_size"] == 2 and ctx.summary["watchlist_hits"] == 1


def test_write_watchlist_is_deterministic_and_nested(tmp_path):
    result = MispImport(indicators=["b.example", "a.example"], notes=["misp: e1 | X"],
                        events=1, attributes=2, used=2)
    first = write_watchlist(result, tmp_path / "sub" / "w.txt")
    second = write_watchlist(result, tmp_path / "sub" / "w2.txt")
    lines_a = first.read_text(encoding="utf-8").splitlines()
    lines_b = second.read_text(encoding="utf-8").splitlines()
    assert [line for line in lines_a if not line.startswith("#")] == ["a.example", "b.example"]
    assert lines_a[1:] == lines_b[1:]  # only the UTC stamp of the header may differ
    assert "# misp: e1 | X" in lines_a
    assert first.parent.is_dir()


def test_multiline_values_never_reach_the_watchlist(tmp_path):
    source = tmp_path / "event.json"
    source.write_text(json.dumps({"Event": _event(attributes=(
        _attr("domain", "evil.example"),
        _attr("domain", "bad.example\n# injected line"),
    ))}), encoding="utf-8")
    result = import_misp(source)
    assert result.indicators == ["evil.example"]  # the newline would fabricate a second IOC
    assert result.skipped["value_multiline"] == 1
    watchlist = write_watchlist(result, tmp_path / "w.txt")
    assert load_watchlist(watchlist) == {"evil.example"}


# --- OpenCTI STIX 2.1 bundles (``forense intel opencti``) ---------------------


def _indicator(pattern: str, ident: str = "indicator--00000000-0000-4000-8000-000000000001",
               labels: tuple = (), created: str = "2026-10-24T10:00:00.000Z", **extra) -> dict:
    obj = {"type": "indicator", "id": ident, "spec_version": "2.1", "created": created,
           "pattern": pattern, "pattern_type": "stix"}
    if labels:
        obj["labels"] = list(labels)
    obj.update(extra)
    return obj


def _bundle(*objects) -> dict:
    return {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-00000000b1e5",
            "objects": list(objects)}


def test_every_stix_path_is_imported(tmp_path):
    source = tmp_path / "bundle.json"
    source.write_text(json.dumps(_bundle(
        _indicator("[file:hashes.'SHA-256' = '" + "A" * 64 + "']", labels=("ransomware",),
                   ident="indicator--00000000-0000-4000-8000-000000000001"),
        _indicator("[file:hashes.sha256 = '" + "b" * 64 + "']",
                   ident="indicator--00000000-0000-4000-8000-000000000002"),
        _indicator("[ipv4-addr:value = '203.0.113.9']",
                   ident="indicator--00000000-0000-4000-8000-000000000003"),
        _indicator("[ipv6-addr:value = '2001:db8::dead']",
                   ident="indicator--00000000-0000-4000-8000-000000000004"),
        _indicator("[domain-name:value = 'EVIL.example']",
                   ident="indicator--00000000-0000-4000-8000-000000000005"),
        _indicator("[hostname:value = 'cdn.evil.example']",
                   ident="indicator--00000000-0000-4000-8000-000000000006"),
        _indicator("[url:value = 'http://evil.example/payload']",
                   ident="indicator--00000000-0000-4000-8000-000000000007"),
        _indicator("[email-addr:value = 'phish@evil.example']",
                   ident="indicator--00000000-0000-4000-8000-000000000008"),
        _indicator("[windows-registry-key:key = 'HKEY_CURRENT_USER\\\\Software\\\\Evil']",
                   ident="indicator--00000000-0000-4000-8000-000000000009"),
        _indicator("[network-traffic:dst_ref.value = '198.51.100.7']",
                   ident="indicator--00000000-0000-4000-8000-00000000000a"),
        _indicator("[file:name = 'invoice.exe']",
                   ident="indicator--00000000-0000-4000-8000-00000000000b"),
        _indicator("[user-agent:user_agent = 'EvilBot/1.0']",
                   ident="indicator--00000000-0000-4000-8000-00000000000c"),
        {"type": "identity", "id": "identity--00000000-0000-4000-8000-00000000b1e6",
         "name": "The Actor"},
        {"type": "relationship", "id": "relationship--00000000-0000-4000-8000-00000000b1e7",
         "relationship_type": "indicates"},
    )), encoding="utf-8")

    result = import_opencti(source)
    assert result.objects == 14 and result.indicators_seen == 12 and result.used == 12
    assert result.duplicates == 0 and result.skipped == {}
    assert set(result.indicators) == {
        "a" * 64, "b" * 64, "203.0.113.9", "2001:db8::dead", "EVIL.example", "cdn.evil.example",
        "http://evil.example/payload", "phish@evil.example", "HKEY_CURRENT_USER\\Software\\Evil",
        "198.51.100.7", "invoice.exe", "EvilBot/1.0"}
    assert result.notes[0] == "opencti: 00000000-0000-4000-8000-000000000001 | ransomware | 2026-10-24"

    out = write_watchlist(result, tmp_path / "watchlist.txt")
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("# Forense watchlist generated from an OpenCTI STIX bundle")
    assert load_watchlist(out) == {i.lower() for i in result.indicators}


def test_opencti_bundle_shapes_and_cross_indicator_dedup(tmp_path):
    first = _indicator("[domain-name:value = 'evil.example']",
                       ident="indicator--00000000-0000-4000-8000-000000000001")
    second = _indicator("[domain-name:value = 'EVIL.example']",
                        ident="indicator--00000000-0000-4000-8000-000000000002")
    third = _indicator("[ipv4-addr:value = '203.0.113.5']",
                       ident="indicator--00000000-0000-4000-8000-000000000003")

    for payload in (_bundle(first, second, third), [first, second, third]):
        source = tmp_path / "export.json"
        source.write_text(json.dumps(payload), encoding="utf-8")
        result = import_opencti(source)
        assert set(result.indicators) == {"evil.example", "203.0.113.5"}
        assert result.duplicates == 1  # the same domain (any case) twice
        assert result.used == 3
        assert len(result.notes) == 3

    no_envelope = tmp_path / "objects.json"
    no_envelope.write_text(json.dumps({"objects": [third]}), encoding="utf-8")
    assert import_opencti(no_envelope).indicators == ["203.0.113.5"]


def test_opencti_unusable_indicators_are_counted_not_guessed(tmp_path):
    source = tmp_path / "bundle.json"
    source.write_text(json.dumps(_bundle(
        _indicator("[file:hashes.'MD5' = '" + "a" * 32 + "' AND file:name = 'evil.exe']"),
        _indicator("[domain-name:value LIKE '%evil%']"),
        _indicator("[domain-name:value != 'safe.example']"),
        _indicator("[domain-name:value IN ('a.example', 'b.example')]"),
        _indicator("[x-custom-thing:value = 'whatever']"),
        _indicator("[file:hashes.'XXX' = '" + "c" * 64 + "']"),
        _indicator("[domain-name:value = 'gone.example']", revoked=True),
        _indicator("[file:name = 'lock.exe']", pattern_type="sigma"),
        _indicator("[ipv4-addr:value = '203.0.113.9']"),
        "not an object",
    )), encoding="utf-8")

    result = import_opencti(source)
    assert result.objects == 9  # the malformed item is not an object
    assert result.indicators_seen == 9
    assert result.used == 1 and result.indicators == ["203.0.113.9"]
    assert result.skipped == {
        "pattern_complex": 1,       # the multi-term AND is not decomposed
        "pattern_not_equality": 3,  # LIKE, != and the IN list
        "pattern_unknown_path": 2,  # the custom object and the unknown hash algorithm
        "revoked": 1,
        "pattern_type:sigma": 1,
        "malformed_object": 1,
    }


def test_opencti_multiline_literal_is_skipped(tmp_path):
    source = tmp_path / "bundle.json"
    source.write_text(json.dumps(_bundle(
        _indicator("[domain-name:value = 'clean.example']",
                   ident="indicator--00000000-0000-4000-8000-000000000001"),
        _indicator("[domain-name:value = 'bad.example\n# fake rule']",
                   ident="indicator--00000000-0000-4000-8000-000000000002"),
    )), encoding="utf-8")
    result = import_opencti(source)
    assert result.indicators == ["clean.example"]  # no phantom line in the watchlist
    assert result.skipped["value_multiline"] == 1


def test_opencti_broken_inputs_are_rejected(tmp_path, monkeypatch):
    with pytest.raises(ForenseError) as exc:
        import_opencti(tmp_path / "nope.json")
    assert exc.value.code == "error.intel_input_missing"

    broken = tmp_path / "broken.json"
    broken.write_text('{"type": "bundle", "objects": [', encoding="utf-8")
    with pytest.raises(ForenseError) as exc:
        import_opencti(broken)
    assert exc.value.code == "error.intel_opencti_invalid"

    for payload in ('"just a string"', '{"type": "bundle"}', '{"objects": "not a list"}',
                    '{"type": "bundle", "objects": []}', "[]"):
        bad = tmp_path / "bad.json"
        bad.write_text(payload, encoding="utf-8")
        with pytest.raises(ForenseError) as exc:
            import_opencti(bad)
        assert exc.value.code == "error.intel_opencti_invalid"

    only_identity = tmp_path / "identity.json"
    only_identity.write_text(json.dumps(
        _bundle({"type": "identity", "id": "identity--00000000-0000-4000-8000-00000000b1e6",
                 "name": "A"})), encoding="utf-8")
    with pytest.raises(ForenseError) as exc:
        import_opencti(only_identity)
    assert exc.value.code == "error.intel_opencti_empty"

    big = tmp_path / "big.json"
    big.write_text('{"objects": [1]}', encoding="utf-8")  # 16 bytes, beyond the patched 4-byte limit
    monkeypatch.setattr("forense.core.intel.MAX_INTEL_BYTES", 4)
    with pytest.raises(ForenseError) as exc:
        import_opencti(big)
    assert exc.value.code == "error.intel_opencti_too_large"
    assert not (tmp_path / "big.watchlist.txt").exists()


def test_cli_intel_opencti(tmp_path, capsys):
    source = tmp_path / "bundle.json"
    source.write_text(json.dumps(_bundle(
        _indicator("[domain-name:value = 'evil.example']",
                   ident="indicator--00000000-0000-4000-8000-00000000b1e6"))), encoding="utf-8")
    out = tmp_path / "custom.txt"
    assert main(["intel", "opencti", str(source), "-o", str(out)]) == EXIT_OK
    message = capsys.readouterr().out
    assert "Watchlist written" in message and "STIX objects" in message
    assert "evil.example" not in message
    assert out.is_file() and not out.read_text().startswith("{")

    # default output name: EXPORT.watchlist.txt next to the bundle
    assert main(["-L", "es", "inteligencia", "opencti", str(source)]) == EXIT_OK
    text = capsys.readouterr().out
    assert "Lista de vigilancia creada" in text and "objetos STIX" in text
    assert (tmp_path / "bundle.watchlist.txt").is_file()

    # the output cannot silently replace the source bundle
    assert main(["intel", "opencti", str(source), "-o", str(source)]) == EXIT_ERROR
    assert "itself" in capsys.readouterr().err
    assert json.loads(source.read_text(encoding="utf-8"))["objects"][0]["type"] == "indicator"

    # a broken bundle is a localized error, not a traceback
    broken = tmp_path / "broken.json"
    broken.write_text("not json", encoding="utf-8")
    assert main(["intel", "opencti", str(broken), "-o", str(tmp_path / "x.txt")]) == EXIT_ERROR
    assert "not a valid OpenCTI STIX bundle" in capsys.readouterr().err
    assert main(["-L", "es", "intel", "opencti", str(tmp_path / "nope.json"),
                 "-o", str(tmp_path / "y.txt")]) == EXIT_ERROR
    assert "No se encuentra la exportación" in capsys.readouterr().err


def test_opencti_watchlist_drives_ioc_findings(tmp_path):
    """The import is only useful if the result feeds the module it was made for."""
    evidence = tmp_path / "drop"
    evidence.mkdir()
    (evidence / "note.txt").write_text("contact cdn.evil.example for the payload\n", encoding="utf-8")
    (evidence / "clean.txt").write_text("nothing to see here\n", encoding="utf-8")
    source = tmp_path / "bundle.json"
    source.write_text(json.dumps(_bundle(
        _indicator("[hostname:value = 'cdn.evil.example']",
                   ident="indicator--00000000-0000-4000-8000-00000000b1e6"),
        _indicator("[file:hashes.'SHA-1' = '" + "e" * 40 + "']",
                   ident="indicator--00000000-0000-4000-8000-00000000b1e7"),
    )), encoding="utf-8")
    result = import_opencti(source)
    watchlist = write_watchlist(result, tmp_path / "watchlist.txt")

    ctx, sink = run("ioc", evidence, tmp_path, watchlist=str(watchlist))
    hits = [f for f in sink.findings if f["code"] == "ioc.watchlist_match"]
    assert [(f["params"]["indicator"], f["params"]["file"]) for f in hits] == \
        [("cdn.evil.example", "note.txt")]
    assert ctx.summary["watchlist_size"] == 2 and ctx.summary["watchlist_hits"] == 1


def test_opencti_notes_are_bounded_and_identified(tmp_path):
    objects = [_indicator(f"[ipv4-addr:value = '10.0.{i // 250}.{i % 250}']",
                          ident=f"indicator--00000000-0000-4000-8000-{i:012d}")
               for i in range(150)]
    source = tmp_path / "bundle.json"
    source.write_text(json.dumps(_bundle(*objects)), encoding="utf-8")

    result = import_opencti(source)
    assert result.used == 150 and len(result.indicators) == 150
    assert len(result.notes) == 101  # first 100 provenance comments + the overflow summary
    assert result.notes[0].startswith("opencti: 00000000-0000-4000-8000-000000000000")
    assert result.notes[-1].startswith("opencti: (+50 more indicator sources omitted")
