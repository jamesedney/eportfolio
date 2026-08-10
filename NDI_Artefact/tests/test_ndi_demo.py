"""Behavioural tests for the synthetic federated identity demo."""
# Tests deliberately exercise private helpers, keys and ledger internals.
# pylint: disable=protected-access,too-many-locals
from __future__ import annotations

import copy
import inspect
import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

import ndi_demo as ndi


# Repository root and CLI entrypoint exercised by subprocess tests.
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ndi_demo.py"

# Exact public class set required by the Figure-3 structural mapping.
EXPECTED_CLASSES = {
    "UserInterface",
    "HolderWallet",
    "InclusionAssistedRoute",
    "SchemeAccessCredentialService",
    "NDISchemeGateway",
    "CryptographicProofPresentationService",
    "AssertionService",
    "IdentityRegister",
    "RPInterface",
    "AdminInterface",
    "ManagementPlane",
    "TrustParticipantRegistry",
    "TamperEvidentAssuranceLedger",
    "AuditorInterface",
}

# Exact directed component relationships required by Figure 3.
EXPECTED_EDGES = {
    ("User Interface", "Holder Wallet"),
    ("User Interface", "Inclusion Assisted Route"),
    ("Holder Wallet", "NDI Scheme Gateway"),
    ("Inclusion Assisted Route", "NDI Scheme Gateway"),
    ("NDI Scheme Gateway", "Scheme Access Credential Service"),
    ("NDI Scheme Gateway", "Trust/Participant Registry"),
    ("NDI Scheme Gateway", "Cryptographic Proof Presentation Service"),
    ("NDI Scheme Gateway", "RP Interface"),
    ("Cryptographic Proof Presentation Service", "Assertion Service"),
    ("Assertion Service", "Identity Register"),
    ("Admin Interface", "Management Plane"),
    ("Management Plane", "Trust/Participant Registry"),
    ("Management Plane", "Tamper-Evident Assurance Ledger"),
    ("Auditor Interface", "Tamper-Evident Assurance Ledger"),
}


def _one(components: dict[str, Any], cls: type) -> Any:
    """Return the single component instance stored under a class name."""
    value = components[cls.COMPONENT_NAME]
    assert isinstance(value, cls)
    return value


def _many(components: dict[str, Any], cls: type) -> tuple[Any, ...]:
    """Return the tuple of component instances stored under a class name."""
    value = components[cls.COMPONENT_NAME]
    assert isinstance(value, tuple) and all(isinstance(item, cls) for item in value)
    return value


def _contained(value: Any, component_ids: set[int]) -> set[int]:
    """Find object ids from ``component_ids`` nested anywhere under ``value``."""
    if id(value) in component_ids:
        return {id(value)}
    if isinstance(value, dict):
        return set().union(*(_contained(item, component_ids) for item in value.values()), set())
    if isinstance(value, (tuple, list, set)):
        return set().union(*(_contained(item, component_ids) for item in value), set())
    return set()


def _assert_architecture(components: dict[str, Any]) -> None:
    """Assert the public API and live object graph match Figure 3 exactly."""
    public = {
        name
        for name, item in inspect.getmembers(ndi, inspect.isclass)
        if item.__module__ == ndi.__name__ and not name.startswith("_")
    }
    assert public == set(ndi.__all__) == EXPECTED_CLASSES
    assert len(ndi.__all__) == 14

    instances: list[tuple[str, Any]] = []
    for label, value in components.items():
        for item in value if isinstance(value, tuple) else (value,):
            instances.append((label, item))
    labels = {id(item): label for label, item in instances}
    edges: set[tuple[str, str]] = set()
    for source, instance in instances:
        for value in vars(instance).values():
            for target_id in _contained(value, set(labels)):
                if labels[target_id] != source:
                    edges.add((source, labels[target_id]))
    assert edges == EXPECTED_EDGES


def _register(components: dict[str, Any], provider_id: str) -> ndi.IdentityRegister:
    """Return the identity register for one provider id."""
    return next(
        item
        for item in _many(components, ndi.IdentityRegister)
        if item.provider_id == provider_id
    )


def _tamper(envelope: dict[str, Any], field: str, value: Any) -> dict[str, Any]:
    """Return a deep-copied envelope with one payload field overwritten."""
    changed = copy.deepcopy(envelope)
    changed["payload"][field] = value
    return changed


def _run_cli(user_input: str) -> subprocess.CompletedProcess[str]:
    """Run the demo CLI as a subprocess with scripted stdin."""
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        input=user_input,
        text=True,
        capture_output=True,
        check=False,
    )


def test_proof_only_disclosure_exposes_derived_statements_not_raw_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RP receipts expose only derived Booleans, never raw provider attributes."""
    components = ndi._build()
    _assert_architecture(components)
    ui = _one(components, ndi.UserInterface)
    gateway = _one(components, ndi.NDISchemeGateway)
    proof_service = _one(components, ndi.CryptographicProofPresentationService)
    assert set(vars(gateway)) == {"access", "registry", "proof_service", "rps", "default_rp"}
    assert not any(isinstance(value, bytes) and len(value) >= 32 for value in vars(ndi).values())

    trace: list[dict[str, str]] = []
    receipt = ui.check("ada", "2468", trace=trace)
    assert set(receipt["payload"]) == ndi.CryptographicProofPresentationService.PAYLOAD_FIELDS
    assert receipt["payload"]["statements"] == {"right_to_work_uk": True}
    assert set(receipt["payload"]["sources"]) == {ndi.NI, ndi.RESIDENCY}
    assert {
        source["check"] for source in receipt["payload"]["sources"].values()
    } == {"has_nino", "uk_resident"}
    assert not ndi._all_keys(receipt["payload"]) & ndi.RPInterface.RAW_FIELDS
    assert receipt["raw_attributes_received"] is False
    disclosed = json.dumps(receipt["payload"])
    assert "QQ123" not in disclosed and '"ada"' not in disclosed and "trace" not in disclosed
    traced_components = {event["component"].split(" [", 1)[0] for event in trace}
    assert {
        ndi.UserInterface.COMPONENT_NAME,
        ndi.HolderWallet.COMPONENT_NAME,
        ndi.SchemeAccessCredentialService.COMPONENT_NAME,
        ndi.TrustParticipantRegistry.COMPONENT_NAME,
        ndi.AssertionService.COMPONENT_NAME,
        ndi.CryptographicProofPresentationService.COMPONENT_NAME,
        ndi.NDISchemeGateway.COMPONENT_NAME,
        ndi.RPInterface.COMPONENT_NAME,
    }.issubset(traced_components)

    incomplete = copy.deepcopy(receipt["payload"])
    incomplete["sources"].pop(ndi.RESIDENCY)
    incomplete_proof = ndi._seal(
        proof_service._presentation_key,
        proof_service.MESSAGE_TYPE,
        proof_service._presentation_kid,
        incomplete,
    )
    with pytest.raises(ValueError, match="incomplete provider evidence"):
        gateway.verify(incomplete_proof, receipt["request"])

    wrong_version = copy.deepcopy(receipt["payload"])
    wrong_version["version"] = 2
    wrong_version_proof = ndi._seal(
        proof_service._presentation_key,
        proof_service.MESSAGE_TYPE,
        proof_service._presentation_kid,
        wrong_version,
    )
    with pytest.raises(ValueError, match="Unsupported derived presentation version"):
        gateway.verify(wrong_version_proof, receipt["request"])

    service = next(
        item
        for item in _many(components, ndi.AssertionService)
        if item.provider_id == ndi.NI
    )
    original = service.issue

    def tampered_assertion(
        record_id: str,
        check: str,
        request: dict[str, Any],
        trace: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Issue a real assertion, then flip ``result`` without resealing."""
        return _tamper(original(record_id, check, request, trace), "result", False)

    monkeypatch.setattr(service, "issue", tampered_assertion)
    with pytest.raises(ValueError, match="HMAC verification failed"):
        ui.check("ada", "2468")


def test_proofs_are_rp_specific_and_cannot_be_replayed_to_another_rp() -> None:
    """Presentations are pairwise-bound to one RP and reject cross-RP replay."""
    components = ndi._build()
    ui = _one(components, ndi.UserInterface)
    gateway = _one(components, ndi.NDISchemeGateway)
    admin = _one(components, ndi.AdminInterface)
    proof_service = _one(components, ndi.CryptographicProofPresentationService)
    admin.register_rp("rp-two", {"right_to_work_check"}, {"right_to_work_uk"})
    gateway.connect_rp(
        ndi.RPInterface(
            "rp-two",
            proof_service._presentation_key,
            proof_service._presentation_kid,
        )
    )
    first = ui.check("ada", "2468")
    second = ui.check("ada", "2468", rp_id="rp-two")
    assert first["payload"]["pairwise_subject"] != second["payload"]["pairwise_subject"]
    with pytest.raises(ValueError):
        gateway.verify(first["proof"], second["request"])
    with pytest.raises(ValueError, match="another RP"):
        gateway.rps["rp-two"].receive(first["proof"], first["request"])
    with pytest.raises(ValueError, match="replay"):
        gateway.verify(first["proof"], first["request"])

    new_jti_payload = copy.deepcopy(first["payload"])
    new_jti_payload["jti"] = secrets.token_urlsafe(18)
    new_jti_proof = ndi._seal(
        proof_service._presentation_key,
        proof_service.MESSAGE_TYPE,
        proof_service._presentation_kid,
        new_jti_payload,
    )
    with pytest.raises(ValueError, match="request replay"):
        gateway.verify(new_jti_proof, first["request"])


def test_verify_time_purpose_binding_rejects_wrong_purpose() -> None:
    """Verification fails when purpose binding or envelope integrity is broken."""
    components = ndi._build()
    ui = _one(components, ndi.UserInterface)
    gateway = _one(components, ndi.NDISchemeGateway)
    receipt = ui.check("ada", "2468")
    _one(components, ndi.AdminInterface).register_rp(
        ndi.RP_ID,
        {"right_to_work_check", "account_recovery"},
        {"right_to_work_uk"},
    )
    second_purpose_request = _one(components, ndi.RPInterface).create_request(
        "account_recovery", "right_to_work_uk"
    )
    with pytest.raises(ValueError, match="wrong request, RP or purpose"):
        gateway.verify(receipt["proof"], second_purpose_request)
    tampered = _tamper(receipt["proof"], "statements", {"right_to_work_uk": False})
    with pytest.raises(ValueError, match="HMAC verification failed"):
        gateway.verify(tampered, receipt["request"])
    wrong_domain = {**receipt["proof"], "type": "ndi-provider-assertion-v1"}
    with pytest.raises(ValueError, match="Malformed authenticated message"):
        gateway.verify(wrong_domain, receipt["request"])


def test_purpose_limitation_rejects_disallowed_purpose() -> None:
    """Disallowed RP purposes are rejected both before and after issuance."""
    components = ndi._build()
    access = _one(components, ndi.SchemeAccessCredentialService)
    gateway = _one(components, ndi.NDISchemeGateway)
    credential = access.login("ada", "2468", "wallet")
    assert credential is not None
    with pytest.raises(ValueError, match="Purpose not allowed"):
        gateway.present(credential, "wallet", purpose="marketing")

    current = ndi._build()
    receipt = _one(current, ndi.UserInterface).check("ada", "2468")
    _one(current, ndi.AdminInterface).register_rp(ndi.RP_ID, set(), set())
    with pytest.raises(ValueError, match="Purpose not allowed"):
        _one(current, ndi.NDISchemeGateway).verify(receipt["proof"], receipt["request"])


def test_disallowed_claim_rejected_before_proof_is_issued(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unauthorised claims fail at policy check before any proof is created."""
    components = ndi._build()
    access = _one(components, ndi.SchemeAccessCredentialService)
    gateway = _one(components, ndi.NDISchemeGateway)
    proof_service = _one(components, ndi.CryptographicProofPresentationService)
    credential = access.login("ada", "2468", "wallet")
    assert credential is not None
    monkeypatch.setattr(proof_service, "create", lambda *args: pytest.fail("proof created"))
    with pytest.raises(ValueError, match="Claim not allowed"):
        gateway.present(credential, "wallet", claim="age_over_18")


def test_unknown_claim_error_for_authorised_but_unrecognised_claim() -> None:
    """Permitted-but-undefined claims raise the dedicated unknown-claim error."""
    components = ndi._build()
    access = _one(components, ndi.SchemeAccessCredentialService)
    gateway = _one(components, ndi.NDISchemeGateway)
    admin = _one(components, ndi.AdminInterface)
    admin.register_rp(ndi.RP_ID, {"right_to_work_check"}, {"new_claim"})
    credential = access.login("ada", "2468", "wallet")
    assert credential is not None
    with pytest.raises(ndi._UnknownClaimError):
        gateway.present(credential, "wallet", claim="new_claim")


def test_expired_proof_fails_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    """Elapsed TTLs invalidate presentations and eventually access credentials."""
    now = [1_000.0]
    monkeypatch.setattr(ndi.time, "time", lambda: now[0])
    components = ndi._build()
    access = _one(components, ndi.SchemeAccessCredentialService)
    gateway = _one(components, ndi.NDISchemeGateway)
    credential = access.login("ada", "2468", "wallet")
    assert credential is not None
    receipt = gateway.present(credential, "wallet", ttl=30)
    assert receipt["payload"]["expires"] == min(
        source["assertion_expires"] for source in receipt["payload"]["sources"].values()
    )
    now[0] += 31
    with pytest.raises(ValueError, match="Proof expired"):
        gateway.verify(receipt["proof"], receipt["request"])
    now[0] += 270
    with pytest.raises(ValueError, match="Invalid access credential"):
        gateway.present(credential, "wallet")


def test_expired_credential_blocks_proof_issuance() -> None:
    """Expired provider records prevent a new proof from being issued."""
    components = ndi._build()
    ui = _one(components, ndi.UserInterface)
    _register(components, ndi.RESIDENCY).expire("ada")
    with pytest.raises(ValueError, match="Expired or revoked record"):
        ui.check("ada", "2468")


def test_revocation_failure_blocks_proof_issuance() -> None:
    """Revoked provider records prevent a new proof from being issued."""
    components = ndi._build()
    _register(components, ndi.NI).revoke("ada")
    with pytest.raises(ValueError, match="Expired or revoked record"):
        _one(components, ndi.UserInterface).check("ada", "2468")


def test_revocation_after_issue_blocks_later_verification() -> None:
    """Post-issue revocation and stale/forged status replies fail verification."""
    components = ndi._build()
    receipt = _one(components, ndi.UserInterface).check("ada", "2468")
    _register(components, ndi.NI).revoke("ada")
    with pytest.raises(ValueError, match="expired or revoked"):
        _one(components, ndi.NDISchemeGateway).verify(receipt["proof"], receipt["request"])

    malformed = ndi._build()
    receipt = _one(malformed, ndi.UserInterface).check("ada", "2468")
    service = next(
        item
        for item in _many(malformed, ndi.AssertionService)
        if item.provider_id == ndi.NI
    )
    original = service.status

    def tampered_status(status_ref: str, rp_id: str, challenge: str) -> dict[str, Any]:
        """Return a status reply whose ``active`` bit was flipped after sealing."""
        return _tamper(original(status_ref, rp_id, challenge), "active", False)

    service.status = tampered_status  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="HMAC verification failed"):
        _one(malformed, ndi.NDISchemeGateway).verify(receipt["proof"], receipt["request"])

    cached = ndi._build()
    cached_service = next(
        item
        for item in _many(cached, ndi.AssertionService)
        if item.provider_id == ndi.NI
    )
    cached_original = cached_service.status
    captured: list[dict[str, Any]] = []

    def capture_status(status_ref: str, rp_id: str, challenge: str) -> dict[str, Any]:
        """Proxy a real status call while retaining a copy for later replay."""
        response = cached_original(status_ref, rp_id, challenge)
        captured.append(copy.deepcopy(response))
        return response

    cached_service.status = capture_status  # type: ignore[method-assign]
    cached_receipt = _one(cached, ndi.UserInterface).check("ada", "2468")
    assert captured

    def replay_status(
        _status_ref: str,
        _rp_id: str,
        _challenge: str,
    ) -> dict[str, Any]:
        """Replay a previously captured status envelope against a new challenge."""
        return copy.deepcopy(captured[0])

    cached_service.status = replay_status  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="Invalid or stale provider status"):
        _one(cached, ndi.NDISchemeGateway).verify(
            cached_receipt["proof"], cached_receipt["request"]
        )

    stale = ndi._build()
    stale_receipt = _one(stale, ndi.UserInterface).check("ada", "2468")
    stale_service = next(
        item
        for item in _many(stale, ndi.AssertionService)
        if item.provider_id == ndi.NI
    )
    stale_original = stale_service.status

    def resealed_status(
        status_ref: str,
        rp_id: str,
        challenge: str,
        checked_at: float,
        next_update: float,
    ) -> dict[str, Any]:
        """Rebuild a validly sealed status reply with attacker-chosen timestamps."""
        response = stale_original(status_ref, rp_id, challenge)
        payload = copy.deepcopy(response["payload"])
        payload["checked_at"] = checked_at
        payload["next_update"] = next_update
        return ndi._seal(
            stale_service._status_key,
            stale_service.STATUS_TYPE,
            stale_service._status_kid,
            payload,
        )

    def old_status(status_ref: str, rp_id: str, challenge: str) -> dict[str, Any]:
        """Produce a status reply whose checked_at is unacceptably old."""
        now = ndi.time.time()
        return resealed_status(status_ref, rp_id, challenge, now - 3, now + 1)

    stale_service.status = old_status  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="Invalid or stale provider status"):
        _one(stale, ndi.NDISchemeGateway).verify(
            stale_receipt["proof"], stale_receipt["request"]
        )

    def future_status(status_ref: str, rp_id: str, challenge: str) -> dict[str, Any]:
        """Produce a status reply whose checked_at is unacceptably in the future."""
        now = ndi.time.time()
        return resealed_status(status_ref, rp_id, challenge, now + 2, now + 3)

    stale_service.status = future_status  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="Invalid or stale provider status"):
        _one(stale, ndi.NDISchemeGateway).verify(
            stale_receipt["proof"], stale_receipt["request"]
        )

    def long_ttl_status(status_ref: str, rp_id: str, challenge: str) -> dict[str, Any]:
        """Produce a status reply whose validity window exceeds the allowed TTL."""
        now = ndi.time.time()
        return resealed_status(
            status_ref,
            rp_id,
            challenge,
            now,
            now + ndi.CryptographicProofPresentationService.STATUS_MAX_TTL_SECONDS + 1,
        )

    stale_service.status = long_ttl_status  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="Invalid or stale provider status"):
        _one(stale, ndi.NDISchemeGateway).verify(
            stale_receipt["proof"], stale_receipt["request"]
        )


def test_uncertified_idp_rejected() -> None:
    """Suspended, rotated, low-assurance or expired providers are untrusted."""
    components = ndi._build()
    ui = _one(components, ndi.UserInterface)
    gateway = _one(components, ndi.NDISchemeGateway)
    receipt = ui.check("ada", "2468")
    _one(components, ndi.AdminInterface).suspend(ndi.NI)
    with pytest.raises(ValueError, match="Untrusted provider"):
        gateway.verify(receipt["proof"], receipt["request"])
    with pytest.raises(ValueError, match="Untrusted provider"):
        ui.check("ada", "2468")

    rotated = ndi._build()
    receipt = _one(rotated, ndi.UserInterface).check("ada", "2468")
    _one(rotated, ndi.AdminInterface).certify(
        ndi.NI,
        secrets.token_bytes(32),
        "ni-assertion-key-2",
        secrets.token_bytes(32),
        "ni-status-key-2",
    )
    with pytest.raises(ValueError, match="no longer matches"):
        _one(rotated, ndi.NDISchemeGateway).verify(receipt["proof"], receipt["request"])

    low = ndi._build()
    ni_service = next(
        item for item in _many(low, ndi.AssertionService) if item.provider_id == ndi.NI
    )
    _one(low, ndi.AdminInterface).certify(
        ndi.NI,
        ni_service._assertion_key,
        ni_service._assertion_kid,
        ni_service._status_key,
        ni_service._status_kid,
        assurance="low",
    )
    with pytest.raises(ValueError, match="Untrusted provider"):
        _one(low, ndi.UserInterface).check("ada", "2468")

    expired = ndi._build()
    ni_service = next(
        item for item in _many(expired, ndi.AssertionService) if item.provider_id == ndi.NI
    )
    _one(expired, ndi.AdminInterface).certify(
        ndi.NI,
        ni_service._assertion_key,
        ni_service._assertion_kid,
        ni_service._status_key,
        ni_service._status_kid,
        validity_seconds=-1,
    )
    with pytest.raises(ValueError, match="Untrusted provider"):
        _one(expired, ndi.UserInterface).check("ada", "2468")


def test_assisted_route_equivalent_to_direct_route() -> None:
    """Assisted and wallet routes yield equivalent outcomes but bind their route."""
    components = ndi._build()
    ui = _one(components, ndi.UserInterface)
    direct = ui.check("ada", "2468", "wallet")
    assisted = ui.check("ada", "2468", "assisted")
    assert direct["qualified"] is True
    assert assisted["qualified"] is True
    assert direct["qualified"] == assisted["qualified"]
    assert direct["payload"]["statements"] == assisted["payload"]["statements"]
    access = _one(components, ndi.SchemeAccessCredentialService)
    credential = access.login("ada", "2468", "wallet")
    assert credential is not None
    with pytest.raises(ValueError, match="Invalid access credential"):
        _one(components, ndi.NDISchemeGateway).present(credential, "assisted")
    access.revoke(credential)
    with pytest.raises(ValueError, match="Invalid access credential"):
        _one(components, ndi.NDISchemeGateway).present(credential, "wallet")
    with pytest.raises(ValueError, match="Unknown route"):
        ui.check("ada", "2468", "typo")

    class FakeGateway:
        """Minimal gateway double that records which route name each call used."""

        def __init__(self) -> None:
            """Create an empty call log."""
            self.calls: list[tuple[str, str]] = []

        def login(self, _username: str, _pin: str, route: str, _trace=None):
            """Record the route and return a stub credential."""
            self.calls.append(("login", route))
            return {"credential": True}

        def present(self, credential, route: str, rp_id=None, trace=None):
            """Record the route and return a qualifying stub receipt."""
            del credential, rp_id, trace
            self.calls.append(("present", route))
            return {"qualified": True}

    fake = FakeGateway()
    wallet = ndi.HolderWallet(fake)  # type: ignore[arg-type]
    issued = wallet.login("ada", "2468")
    assert issued is not None and wallet.present(issued)["qualified"] is True
    assert fake.calls == [("login", "wallet"), ("present", "wallet")]
    assert set(vars(wallet)) == {"gateway"}


def test_tamper_evident_ledger_detects_memory_mutation() -> None:
    """In-memory ledger mutation, rewrite and rollback are detected by the auditor."""
    components = ndi._build()
    ledger = _one(components, ndi.TamperEvidentAssuranceLedger)
    auditor = _one(components, ndi.AuditorInterface)
    assert auditor.valid()
    snapshot = auditor.view()
    snapshot[0]["data"]["provider_id"] = "copy-only"
    assert auditor.valid()
    assert not auditor.verify_snapshot(snapshot)
    ledger._entries[0]["data"]["provider_id"] = "changed"
    assert not auditor.valid()

    rewritten = ndi._build()
    auditor = _one(rewritten, ndi.AuditorInterface)
    snapshot = auditor.view()
    snapshot[0]["data"]["provider_id"] = "fully-rewritten"
    previous = "0" * 64
    for entry in snapshot:
        entry["previous_hash"] = previous
        entry["hash"] = ndi.TamperEvidentAssuranceLedger._hash(entry)
        previous = entry["hash"]
    assert not auditor.verify_snapshot(snapshot)

    rollback = ndi._build()
    ledger = _one(rollback, ndi.TamperEvidentAssuranceLedger)
    auditor = _one(rollback, ndi.AuditorInterface)
    assert auditor.valid()
    ledger._entries.pop()
    assert not auditor.valid()


def test_tamper_evident_ledger_persists_hash_chained_json_file() -> None:
    """Saved ledger JSON stays authentic only while its chain and tags remain intact."""
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        path = Path(directory) / "ledger.json"
        key = secrets.token_bytes(32)
        ledger = ndi.TamperEvidentAssuranceLedger(key, "test-audit-key")
        ledger.append("provider_certified", {"provider_id": "idp-one"})
        ledger.append("rp_registered", {"rp_id": "rp-one"})
        ledger.save(path)
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert saved[1]["previous_hash"] == saved[0]["hash"]
        assert ndi.TamperEvidentAssuranceLedger.load(
            path, key, "test-audit-key"
        ).valid()
        saved[0]["data"]["provider_id"] = "changed"
        previous = "0" * 64
        for entry in saved:
            entry["previous_hash"] = previous
            entry["hash"] = ndi.TamperEvidentAssuranceLedger._hash(entry)
            previous = entry["hash"]
        path.write_text(json.dumps(saved), encoding="utf-8")
        assert not ndi.TamperEvidentAssuranceLedger.load(
            path, key, "test-audit-key"
        ).valid()


def test_cli_login_accepts_valid_account_and_rejects_bad_pin() -> None:
    """CLI accepts Ada's PIN, rejects a bad PIN, then shows a valid presentation."""
    result = _run_cli("2\n1\n2468\n2\n1\n0000\n3\n0\n")
    assert result.returncode == 0
    assert "Login: VALID" in result.stdout
    assert "Derived result: PASS AND PASS = PASS" in result.stdout
    assert "Raw provider attributes disclosed: NO" in result.stdout
    assert "Authenticated presentation: VALID" in result.stdout
    assert "Login: INVALID" in result.stdout
    assert "Derived result: Right-to-work eligibility = TRUE" in result.stdout
    assert "Verified component flow" not in result.stdout


def test_qualified_user_submits_a_valid_minimised_proof() -> None:
    """CLI records view plus Ada's check show a minimised successful RP proof."""
    result = _run_cli("1\n2\n1\n2468\n3\n0\n")
    assert result.returncode == 0
    assert "ada: national_insurance_number=QQ123" in result.stdout
    assert "ben: national_insurance_number=<missing>" in result.stdout
    assert "Derived result: PASS AND PASS = PASS" in result.stdout
    assert "RP received: Right-to-work eligibility = TRUE" in result.stdout
    assert "Raw provider attributes disclosed: NO" in result.stdout
    payload = result.stdout.split("LAST SUCCESSFUL RP PRESENTATION", 1)[1].split(
        "\n1 records", 1
    )[0]
    assert "Relying party: Example Employer" in payload
    assert "Purpose: Right-to-work eligibility check" in payload
    assert "Derived result: Right-to-work eligibility = TRUE" in payload
    assert "Verified sources: 2/2 | Fresh status: 2/2" in payload
    assert "Authentication: VALID" in payload
    assert "Bindings (request, RP, purpose and nonce): VALID" in payload
    assert "QQ123" not in payload and "national_insurance_number" not in payload
    assert "Raw provider attributes: NONE" in payload
    assert "Provider-local trace: NONE" in payload
    for internal in (
        "HMAC tag:",
        "request_nonce",
        "pairwise_subject",
        "status_ref",
        "kid=",
        "right_to_work_uk",
    ):
        assert internal not in payload
    _assert_architecture(ndi._build())
    assert "6 classes" not in result.stdout
    assert "Verified component flow" not in result.stdout


def test_non_qualifying_user_submits_a_valid_negative_proof() -> None:
    """Ben's negative result is still a valid presentation with intact audit views."""
    result = _run_cli("2\n2\n1357\n3\n4\n5\n0\n")
    assert result.returncode == 0
    assert "Derived result: FAIL AND PASS = FAIL" in result.stdout
    assert "Derived result: Right-to-work eligibility = FALSE" in result.stdout
    payload = result.stdout.split("LAST SUCCESSFUL RP PRESENTATION", 1)[1].split(
        "\n1 records", 1
    )[0]
    assert "Raw provider attributes: NONE" in payload
    assert "Provider-local trace: NONE" in payload
    audit = result.stdout.split("AUDIT LOG", 1)[1].split(
        "\n1 records", 1
    )[0]
    assert "Snapshot authentication: PASS" in audit
    assert "Provider certified: National Insurance" in audit
    assert "provider_id=idp-national-insurance" in audit
    assert "Provider certified: UK Residency" in audit
    assert "provider_id=idp-residency" in audit
    assert "Relying party registered: Example Employer" in audit
    assert "rp_id=rp-example-employer" in audit
    assert "right_to_work_check -> right_to_work_uk" in audit
    assert "Events recorded: 3" in audit
    for raw in ("QQ123", "national_insurance_number", '"ada"', '"ben"'):
        assert raw not in audit
    ledger = result.stdout.split("TAMPER-EVIDENT LEDGER", 1)[1].split(
        "\n1 records", 1
    )[0]
    assert "READ-ONLY LEDGER VIEW" in ledger
    assert "Stored entry sequence: START -> 1 -> 2 -> 3" in ledger
    assert "Entries checked: 3" in ledger
    assert "Verification: PASS - the current snapshot's order" in ledger
    assert "Run-local checkpoint: VERIFIED AT ENTRY 3" in ledger
    assert "Status: AUTHENTICATED CURRENT SNAPSHOT" in ledger
    assert "rewritten-provider" not in ledger
    assert "TAMPER TEST" not in result.stdout
    assert "TAMPERING DETECTED" not in result.stdout
    assert "Verified component flow" not in result.stdout
