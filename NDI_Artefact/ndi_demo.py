"""Synthetic single-process federated right-to-work demonstrator.

Models the fourteen Figure 3 components using synthetic records and
per-run HMAC keys. It demonstrates responsibilities and message integrity,
not production federation, advanced cryptography or a legal decision. The
synthetic National Insurance and residency rule is not the statutory UK
right-to-work process [GOV-RTW].

Technical references (all accessed 10 August 2026):

[PY-JSON] Python Software Foundation, ``json - JSON encoder and decoder``.
    https://docs.python.org/3/library/json.html
[PY-HMAC] Python Software Foundation, ``hmac - Keyed-Hashing for Message
    Authentication``. https://docs.python.org/3/library/hmac.html
[PY-HASHLIB] Python Software Foundation, ``hashlib - Secure hashes and
    message digests``. https://docs.python.org/3/library/hashlib.html
[PY-SECRETS] Python Software Foundation, ``secrets - Generate secure random
    numbers for managing secrets``. https://docs.python.org/3/library/secrets.html
[RFC2104] Krawczyk, H., Bellare, M. and Canetti, R. (1997), ``HMAC:
    Keyed-Hashing for Message Authentication``. https://www.rfc-editor.org/rfc/rfc2104
[RFC8018] Moriarty, K., Kaliski, B. and Rusch, A. (2017), ``PKCS #5:
    Password-Based Cryptography Specification Version 2.1``.
    https://www.rfc-editor.org/rfc/rfc8018
[NIST63C] Temoshok, D. et al. (2025), ``Digital Identity Guidelines:
    Federation and Assertions``, NIST SP 800-63C-4.
    https://doi.org/10.6028/NIST.SP.800-63C-4
[SK99] Schneier, B. and Kelsey, J. (1999), ``Secure Audit Logs to Support
    Computer Forensics``, ACM TISSEC, 2(2), pp. 159-176.
    https://doi.org/10.1145/317087.317089
[GOV-RTW] Home Office (no date), ``Right to work checks: an employer's
    guide``. https://www.gov.uk/government/publications/right-to-work-checks-employers-guide
"""
from __future__ import annotations

import copy
import getpass
import hashlib
import hmac
import json
import os
import secrets
import time
import sys
from pathlib import Path
from typing import Any


# Synthetic participant identifiers used throughout the demo world.
NI = "idp-national-insurance"
RESIDENCY = "idp-residency"
RP_ID = "rp-example-employer"

# Claim rules evaluated by the trust registry during authorisation.
# Each rule lists the provider checks and the minimum assurance floor.
RULES = {
    "right_to_work_uk": {
        "version": 1,
        "minimum_assurance": "substantial",
        "checks": ((NI, "has_nino"), (RESIDENCY, "uk_resident")),
    }
}

# Ordered assurance labels used to compare provider certification strength.
ASSURANCE = {"low": 1, "substantial": 2, "high": 3}

# Exact field set required of every HMAC-authenticated message envelope.
ENVELOPE_FIELDS = {"alg", "type", "kid", "payload", "tag"}


def _canonical(value: Any) -> bytes:
    """Return repeatable key-sorted JSON bytes for constrained payloads.

    This uses documented ``json.dumps`` options [PY-JSON]; it is not a claim
    of full standards-based canonical JSON.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _tag(key: bytes, message_type: str, kid: str, payload: dict[str, Any]) -> str:
    """Compute an HMAC-SHA256 message tag [PY-HMAC, RFC2104]."""
    signed = {"alg": "HMAC-SHA256", "type": message_type, "kid": kid, "payload": payload}
    return hmac.new(key, _canonical(signed), hashlib.sha256).hexdigest()


def _seal(key: bytes, message_type: str, kid: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap a payload in an authenticated HMAC envelope."""
    return {
        "alg": "HMAC-SHA256",
        "type": message_type,
        "kid": kid,
        "payload": copy.deepcopy(payload),
        "tag": _tag(key, message_type, kid, payload),
    }


def _open(
    key: bytes,
    message_type: str,
    kid: str,
    envelope: dict[str, Any],
) -> dict[str, Any]:
    """Verify an envelope using ``compare_digest`` and return its payload.

    The comparison follows the timing-analysis guidance in [PY-HMAC].
    """
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise ValueError("Malformed authenticated message")
    payload = envelope.get("payload")
    if (
        envelope.get("alg") != "HMAC-SHA256"
        or envelope.get("type") != message_type
        or envelope.get("kid") != kid
        or not isinstance(payload, dict)
        or not isinstance(envelope.get("tag"), str)
    ):
        raise ValueError("Malformed authenticated message")
    expected = _tag(key, message_type, kid, payload)
    if not hmac.compare_digest(envelope["tag"], expected):
        raise ValueError("HMAC verification failed")
    return copy.deepcopy(payload)


def _text_tag(key: bytes, domain: str, value: str) -> str:
    """HMAC a domain-separated string into a stable opaque identifier."""
    return hmac.new(key, f"{domain}|{value}".encode(), hashlib.sha256).hexdigest()


def _pin_hash(pin: str, salt: bytes) -> bytes:
    """Derive a salted PIN digest with PBKDF2-HMAC-SHA256.

    The construction follows [PY-HASHLIB, RFC8018]. The demonstrator's
    iteration count is not presented as production password-storage advice.
    """
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 120_000)


def _require(value: dict[str, Any], fields: set[str], name: str) -> None:
    """Assert that a dict has an exact field set and supported version."""
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"Invalid {name} schema")
    if "version" in fields and value.get("version") != 1:
        raise ValueError(f"Unsupported {name} version")


def _event(
    trace: list[dict[str, str]] | None,
    component: str,
    action: str,
    result: str,
) -> None:
    """Append a component action to an optional operator/debug trace."""
    if trace is not None:
        trace.append({"component": component, "action": action, "result": result})


def _all_keys(value: Any) -> set[str]:
    """Collect every dict key found anywhere in a nested structure."""
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value), set())
    return set()


class _UnknownClaimError(ValueError):
    """Raised when an RP is permitted a claim that has no rule definition."""


class _Route:
    """Shared base for holder routes that login and present via the gateway."""

    COMPONENT_NAME = ""
    name = ""

    def __init__(self, gateway: NDISchemeGateway) -> None:
        """Attach this route to the shared NDI scheme gateway."""
        self.gateway = gateway

    def login(
        self,
        username: str,
        pin: str,
        trace: list[dict[str, str]] | None = None,
    ) -> dict[str, Any] | None:
        """Authenticate the holder and obtain a route-bound access credential."""
        _event(trace, type(self).COMPONENT_NAME, "route", f"submitted via {self.name}")
        return self.gateway.login(username, pin, self.name, trace)

    def present(
        self,
        credential: dict[str, Any],
        trace: list[dict[str, str]] | None = None,
        rp_id: str | None = None,
    ) -> dict[str, Any]:
        """Present an access credential to complete a relying-party check."""
        return self.gateway.present(credential, self.name, rp_id=rp_id, trace=trace)


class UserInterface:
    """Operator-facing entrypoint that selects wallet or assisted routes."""
    COMPONENT_NAME = "User Interface"

    def __init__(self, wallet: HolderWallet, assisted: InclusionAssistedRoute) -> None:
        """Store the available holder routes."""
        self.wallet = wallet
        self.assisted = assisted

    def check(
        self,
        username: str,
        pin: str,
        route: str = "wallet",
        trace: list[dict[str, str]] | None = None,
        rp_id: str | None = None,
    ) -> dict[str, Any]:
        """Run a full right-to-work check for one holder via a chosen route."""
        routes = {"wallet": self.wallet, "assisted": self.assisted}
        if route not in routes:
            raise ValueError("Unknown route")
        selected = routes[route]
        _event(trace, self.COMPONENT_NAME, "route selection", selected.COMPONENT_NAME)
        credential = selected.login(username, pin, trace)
        if credential is None:
            raise ValueError("Sign-in failed")
        return selected.present(credential, trace, rp_id)


class HolderWallet(_Route):
    """Direct digital-wallet route used by the interactive CLI check."""
    COMPONENT_NAME = "Holder Wallet"
    name = "wallet"


class InclusionAssistedRoute(_Route):
    """Assisted inclusion route that shares the same gateway protocol path."""
    COMPONENT_NAME = "Inclusion Assisted Route"
    name = "assisted"


class SchemeAccessCredentialService:
    """Authenticates holders and issues short-lived route-bound credentials."""
    COMPONENT_NAME = "Scheme Access Credential Service"
    MESSAGE_TYPE = "ndi-access-credential-v1"
    PAYLOAD_FIELDS = {"session", "route", "issued_at", "expires"}

    def __init__(self, key: bytes, kid: str) -> None:
        """Create an empty credential service backed by one HMAC key."""
        self._key = key
        self._kid = kid
        self._users: dict[str, dict[str, Any]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._revoked: set[str] = set()

    def add_user(self, username: str, pin: str, records: dict[str, str]) -> None:
        """Register a holder account and mapped provider record ids."""
        canonical = username.casefold()
        salt = secrets.token_bytes(16)
        self._users[canonical] = {
            "salt": salt,
            "pin_hash": _pin_hash(pin, salt),
            "records": dict(records),
        }

    def login(
        self,
        username: str,
        pin: str,
        route: str,
        trace: list[dict[str, str]] | None = None,
    ) -> dict[str, Any] | None:
        """Validate a PIN and mint a five-minute route-bound credential."""
        user = self._users.get(username.casefold())
        if user is None or not hmac.compare_digest(
            user["pin_hash"], _pin_hash(pin, user["salt"])
        ):
            _event(trace, self.COMPONENT_NAME, "authentication", "rejected")
            return None
        session_id = secrets.token_urlsafe(18)
        issued_at = time.time()
        expires = time.time() + 300
        self._sessions[session_id] = {
            "route": route,
            "records": dict(user["records"]),
            "expires": expires,
        }
        payload = {
            "session": session_id,
            "route": route,
            "issued_at": issued_at,
            "expires": expires,
        }
        _event(
            trace,
            self.COMPONENT_NAME,
            "authentication",
            "valid; issued route-bound credential",
        )
        return _seal(self._key, self.MESSAGE_TYPE, self._kid, payload)

    def resolve(
        self,
        credential: dict[str, Any],
        route: str,
        trace: list[dict[str, str]] | None = None,
    ) -> dict[str, str]:
        """Validate a credential and return the holder's provider record ids."""
        payload = _open(self._key, self.MESSAGE_TYPE, self._kid, credential)
        _require(payload, self.PAYLOAD_FIELDS, "access credential")
        session_id = payload.get("session")
        session = self._sessions.get(str(session_id))
        if self._session_rejected(payload, session, session_id, route):
            raise ValueError("Invalid access credential")
        _event(
            trace,
            self.COMPONENT_NAME,
            "credential validation",
            "HMAC, route, session and expiry valid",
        )
        return dict(session["records"])

    def _session_rejected(
        self,
        payload: dict[str, Any],
        session: dict[str, Any] | None,
        session_id: Any,
        route: str,
    ) -> bool:
        """Return True when a resolved access session must be rejected."""
        if session is None or session_id in self._revoked:
            return True
        if payload.get("route") != route or session["route"] != route:
            return True
        if float(payload.get("issued_at", 0)) > time.time():
            return True
        if float(payload.get("expires", 0)) <= time.time():
            return True
        return float(session["expires"]) != float(payload["expires"])

    def revoke(self, credential: dict[str, Any]) -> None:
        """Mark the session inside a credential as revoked."""
        payload = _open(self._key, self.MESSAGE_TYPE, self._kid, credential)
        _require(payload, self.PAYLOAD_FIELDS, "access credential")
        self._revoked.add(str(payload["session"]))


class NDISchemeGateway:
    """Central scheme orchestrator for login, policy, proof and verification."""
    COMPONENT_NAME = "NDI Scheme Gateway"

    def __init__(
        self,
        access: SchemeAccessCredentialService,
        registry: TrustParticipantRegistry,
        proof_service: CryptographicProofPresentationService,
        rp: RPInterface,
    ) -> None:
        """Wire the gateway to access, registry, proof and default RP services."""
        self.access = access
        self.registry = registry
        self.proof_service = proof_service
        self.rps = {rp.rp_id: rp}
        self.default_rp = rp.rp_id

    def connect_rp(self, rp: RPInterface) -> None:
        """Register or replace a relying-party interface on this gateway."""
        self.rps[rp.rp_id] = rp

    def login(
        self,
        username: str,
        pin: str,
        route: str,
        trace: list[dict[str, str]] | None = None,
    ) -> dict[str, Any] | None:
        """Delegate holder authentication to the access-credential service."""
        return self.access.login(username, pin, route, trace)

    def present(
        self,
        credential: dict[str, Any],
        route: str,
        purpose: str = "right_to_work_check",
        claim: str = "right_to_work_uk",
        rp_id: str | None = None,
        trace: list[dict[str, str]] | None = None,
        ttl: int = 60,
    ) -> dict[str, Any]:
        """Resolve a holder credential into a verified RP eligibility receipt."""
        rp = self.rps[rp_id or self.default_rp]
        request = rp.create_request(purpose, claim, ttl)
        record_ids = self.access.resolve(credential, route, trace)
        rule = self.registry.authorise(request)
        _event(
            trace,
            self.registry.COMPONENT_NAME,
            "policy decision",
            f"rule v{rule['version']} permits {purpose}/{claim}",
        )
        trust = self._trusted_sources(rule, trace)
        proof = self.proof_service.create(record_ids, rule, trust, request, trace)
        return self.verify(proof, request, trace)

    def _trusted_sources(
        self,
        rule: dict[str, Any],
        trace: list[dict[str, str]] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Resolve each rule check to a currently trusted provider record."""
        trusted: dict[str, dict[str, Any]] = {}
        for provider_id, _ in rule["checks"]:
            provider = self.registry.provider(provider_id, rule["minimum_assurance"])
            trusted[provider_id] = provider
            _event(
                trace,
                self.registry.COMPONENT_NAME,
                "provider trust",
                (
                    f"{provider_id}: {provider['assurance']} / "
                    f"{provider['key_id']} / revision {provider['revision']}"
                ),
            )
        return trusted

    def verify(
        self,
        proof: dict[str, Any],
        request: dict[str, Any],
        trace: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Recheck policy and status, then ask the RP to accept a presentation."""
        payload = self.proof_service.open_proof(proof)
        rule = self.registry.authorise(request)
        trust = self._trusted_sources(rule, trace)
        expected = dict(rule["checks"])
        sources = payload.get("sources")
        if not isinstance(sources, dict) or set(sources) != set(expected):
            raise ValueError("Proof has incomplete provider evidence")
        if (
            payload.get("rule_version") != rule["version"]
            or payload.get("claim") != request["claim"]
        ):
            raise ValueError("Proof uses a stale or incorrect rule")
        for provider_id, check in expected.items():
            source = sources[provider_id]
            _require(
                source,
                {
                    "provider",
                    "check",
                    "status_ref",
                    "key_id",
                    "trust_revision",
                    "assertion_expires",
                },
                "proof source",
            )
            provider = trust[provider_id]
            if (
                source["provider"] != provider_id
                or source["check"] != check
                or source["key_id"] != provider["key_id"]
                or source["trust_revision"] != provider["revision"]
            ):
                raise ValueError("Proof source no longer matches participant trust state")
        self.proof_service.sources_active(payload, request, trust, trace)
        _event(
            trace,
            self.COMPONENT_NAME,
            "verification",
            "policy rechecked; exact sources and fresh status valid",
        )
        receipt = self.rps[request["rp_id"]].receive(proof, request, trace)
        receipt["verification"].update(
            {
                "policy_rechecked": True,
                "sources_verified": len(sources),
                "fresh_status": len(sources),
            }
        )
        return receipt


class CryptographicProofPresentationService:
    """Build and validate minimised derived presentations from assertions.

    Here ``proof`` means an authenticated derived result, not a digital
    signature, zero-knowledge proof or independently verifiable attestation.
    """
    COMPONENT_NAME = "Cryptographic Proof Presentation Service"
    MESSAGE_TYPE = "ndi-derived-presentation-v1"
    PAYLOAD_FIELDS = {
        "version",
        "jti",
        "request_id",
        "request_nonce",
        "rp_id",
        "purpose",
        "claim",
        "rule_version",
        "issued_at",
        "expires",
        "pairwise_subject",
        "sources",
        "statements",
    }
    STATUS_CLOCK_SKEW_SECONDS = 1.0
    STATUS_MAX_TTL_SECONDS = 5.0

    def __init__(
        self,
        services: dict[str, AssertionService],
        presentation_key: bytes,
        presentation_kid: str,
    ) -> None:
        """Store provider assertion services and the presentation HMAC key."""
        self.services = dict(services)
        self._presentation_key = presentation_key
        self._presentation_kid = presentation_kid

    def create(
        self,
        record_ids: dict[str, str],
        rule: dict[str, Any],
        trust: dict[str, dict[str, Any]],
        request: dict[str, Any],
        trace: list[dict[str, str]] | None,
    ) -> dict[str, Any]:
        """Collect provider assertions and seal a same-subject derived proof."""
        results: list[bool] = []
        subjects: set[str] = set()
        sources: dict[str, dict[str, Any]] = {}
        assertion_expiries: list[float] = []
        for provider_id, check in rule["checks"]:
            service = self.services[provider_id]
            assertion = service.issue(record_ids[provider_id], check, request, trace)
            provider = trust[provider_id]
            payload = _open(
                provider["assertion_key"],
                AssertionService.ASSERTION_TYPE,
                provider["key_id"],
                assertion,
            )
            _require(payload, AssertionService.ASSERTION_FIELDS, "provider assertion")
            expected = (
                provider_id,
                request["id"],
                request["nonce"],
                request["rp_id"],
                request["purpose"],
                request["claim"],
                check,
                provider["key_id"],
            )
            actual = tuple(
                payload.get(name)
                for name in (
                    "provider",
                    "request_id",
                    "request_nonce",
                    "rp_id",
                    "purpose",
                    "claim",
                    "check",
                    "key_id",
                )
            )
            if actual != expected or not isinstance(payload.get("result"), bool):
                raise ValueError("Invalid provider assertion")
            if float(payload.get("expires", 0)) <= time.time():
                raise ValueError("Provider assertion expired")
            result = payload["result"]
            results.append(result)
            subjects.add(str(payload["pairwise_subject"]))
            assertion_expiries.append(float(payload["expires"]))
            sources[provider_id] = {
                "provider": provider_id,
                "check": check,
                "status_ref": str(payload["status_ref"]),
                "key_id": provider["key_id"],
                "trust_revision": provider["revision"],
                "assertion_expires": float(payload["expires"]),
            }
            _event(
                trace,
                self.COMPONENT_NAME,
                "assertion verification",
                f"{provider_id}: HMAC, issuer and request bindings valid",
            )
        if len(subjects) != 1:
            raise ValueError("Provider assertions refer to different people")
        issued_at = time.time()
        payload = {
            "version": 1,
            "jti": secrets.token_urlsafe(18),
            "request_id": request["id"],
            "request_nonce": request["nonce"],
            "rp_id": request["rp_id"],
            "purpose": request["purpose"],
            "claim": request["claim"],
            "rule_version": rule["version"],
            "issued_at": issued_at,
            "expires": min(float(request["expires"]), *assertion_expiries),
            "pairwise_subject": subjects.pop(),
            "sources": sources,
            "statements": {request["claim"]: all(results)},
        }
        _event(
            trace,
            self.COMPONENT_NAME,
            "derivation",
            f"same-subject valid; {len(results)} Boolean results combined",
        )
        return _seal(
            self._presentation_key,
            self.MESSAGE_TYPE,
            self._presentation_kid,
            payload,
        )

    def open_proof(self, proof: dict[str, Any]) -> dict[str, Any]:
        """Open and schema-validate a derived-presentation envelope."""
        payload = _open(
            self._presentation_key,
            self.MESSAGE_TYPE,
            self._presentation_kid,
            proof,
        )
        _require(payload, self.PAYLOAD_FIELDS, "derived presentation")
        return payload

    def sources_active(
        self,
        payload: dict[str, Any],
        request: dict[str, Any],
        trust: dict[str, dict[str, Any]],
        trace: list[dict[str, str]] | None = None,
    ) -> None:
        """Require fresh challenge-bound active status for every proof source."""
        verifier_challenge = secrets.token_urlsafe(24)
        verification_started = time.time()
        for provider_id, source in payload["sources"].items():
            provider = trust[provider_id]
            response = self.services[provider_id].status(
                str(source["status_ref"]),
                request["rp_id"],
                verifier_challenge,
            )
            status = _open(
                provider["status_key"],
                AssertionService.STATUS_TYPE,
                provider["status_kid"],
                response,
            )
            _require(status, AssertionService.STATUS_FIELDS, "provider status")
            expected = (
                provider_id,
                provider["status_kid"],
                source["status_ref"],
                request["rp_id"],
                verifier_challenge,
            )
            actual = tuple(
                status.get(name)
                for name in ("provider", "key_id", "status_ref", "rp_id", "challenge")
            )
            now = time.time()
            checked_at = float(status.get("checked_at", 0))
            next_update = float(status.get("next_update", 0))
            if self._status_rejected(
                status,
                actual,
                expected,
                checked_at,
                next_update,
                verification_started,
                now,
            ):
                raise ValueError("Invalid or stale provider status")
            if not status["active"]:
                raise ValueError("A provider record is expired or revoked")
            _event(
                trace,
                self.COMPONENT_NAME,
                "status verification",
                f"{provider_id}: fresh authenticated active status",
            )

    def _status_rejected(
        self,
        status: dict[str, Any],
        actual: tuple[Any, ...],
        expected: tuple[Any, ...],
        checked_at: float,
        next_update: float,
        verification_started: float,
        now: float,
    ) -> bool:
        """Return True when a live status reply fails freshness or binding checks."""
        if actual != expected or not isinstance(status.get("active"), bool):
            return True
        if checked_at < verification_started - self.STATUS_CLOCK_SKEW_SECONDS:
            return True
        if checked_at > now + self.STATUS_CLOCK_SKEW_SECONDS:
            return True
        if next_update <= now or next_update <= checked_at:
            return True
        return next_update - checked_at > self.STATUS_MAX_TTL_SECONDS


class AssertionService:
    """Issue provider-local Boolean assertions and live status replies.

    The shared demo subject key lets two provider results be compared inside
    one process. It is not a provider-separated deployment of the pairwise
    pseudonymous identifiers described in [NIST63C].
    """
    COMPONENT_NAME = "Assertion Service"
    ASSERTION_TYPE = "ndi-provider-assertion-v1"
    STATUS_TYPE = "ndi-provider-status-v1"
    ASSERTION_FIELDS = {
        "version",
        "provider",
        "request_id",
        "request_nonce",
        "rp_id",
        "purpose",
        "claim",
        "check",
        "result",
        "pairwise_subject",
        "status_ref",
        "key_id",
        "issued_at",
        "expires",
    }
    STATUS_FIELDS = {
        "version",
        "provider",
        "key_id",
        "status_ref",
        "rp_id",
        "challenge",
        "active",
        "checked_at",
        "next_update",
    }

    def __init__(
        self,
        provider_id: str,
        register: IdentityRegister,
        assertion_key: bytes,
        assertion_kid: str,
        status_key: bytes,
        status_kid: str,
        subject_key: bytes,
    ) -> None:
        """Bind one provider register to assertion and status HMAC keys."""
        self.provider_id = provider_id
        self.register = register
        self._assertion_key = assertion_key
        self._assertion_kid = assertion_kid
        self._status_key = status_key
        self._status_kid = status_kid
        self._subject_key = subject_key

    def issue(
        self,
        record_id: str,
        check: str,
        request: dict[str, Any],
        trace: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Evaluate a local Boolean check and seal a request-bound assertion."""
        record = self.register.get(record_id)
        if check == "has_nino":
            result = bool(record.get("national_insurance_number"))
        elif check == "uk_resident":
            result = record.get("country") == "GB"
        else:
            raise ValueError(f"Unknown provider check: {check}")
        issued_at = time.time()
        payload = {
            "version": 1,
            "provider": self.provider_id,
            "request_id": request["id"],
            "request_nonce": request["nonce"],
            "rp_id": request["rp_id"],
            "purpose": request["purpose"],
            "claim": request["claim"],
            "check": check,
            "result": result,
            "pairwise_subject": _text_tag(
                self._subject_key,
                "pairwise-subject",
                f"{record['subject']}|{request['rp_id']}",
            ),
            "status_ref": _text_tag(
                self._status_key,
                "status-reference",
                f"{record_id}|{request['rp_id']}",
            ),
            "key_id": self._assertion_kid,
            "issued_at": issued_at,
            "expires": min(float(request["expires"]), issued_at + 60),
        }
        _event(
            trace,
            f"{self.COMPONENT_NAME} [{self.provider_id}]",
            "local check",
            f"{check}={result}; assertion HMAC created",
        )
        return _seal(
            self._assertion_key,
            self.ASSERTION_TYPE,
            self._assertion_kid,
            payload,
        )

    def status(self, status_ref: str, rp_id: str, challenge: str) -> dict[str, Any]:
        """Answer whether the record behind a status reference is still active."""
        active = False
        for record_id in self.register.record_ids():
            expected = _text_tag(
                self._status_key,
                "status-reference",
                f"{record_id}|{rp_id}",
            )
            if hmac.compare_digest(status_ref, expected):
                active = self.register.active(record_id)
                break
        checked_at = time.time()
        payload = {
            "version": 1,
            "provider": self.provider_id,
            "key_id": self._status_kid,
            "status_ref": status_ref,
            "rp_id": rp_id,
            "challenge": challenge,
            "active": active,
            "checked_at": checked_at,
            "next_update": checked_at
            + CryptographicProofPresentationService.STATUS_MAX_TTL_SECONDS,
        }
        return _seal(
            self._status_key,
            self.STATUS_TYPE,
            self._status_kid,
            payload,
        )


class IdentityRegister:
    """In-memory provider database of synthetic holder attribute records."""
    COMPONENT_NAME = "Identity Register"

    def __init__(self, provider_id: str) -> None:
        """Create an empty register for one provider."""
        self.provider_id = provider_id
        self._records: dict[str, dict[str, Any]] = {}
        self._revoked: set[str] = set()

    def add(self, record_id: str, **attributes: Any) -> None:
        """Insert or replace a local record and its attributes."""
        self._records[record_id] = {
            "subject": record_id,
            "expires": attributes.pop("expires", time.time() + 3600),
            **attributes,
        }

    def get(self, record_id: str) -> dict[str, Any]:
        """Return a deep copy of an active record."""
        if not self.active(record_id):
            raise ValueError(f"Expired or revoked record: {record_id}")
        return copy.deepcopy(self._records[record_id])

    def active(self, record_id: str) -> bool:
        """Report whether a record exists, is unrevoked and unexpired."""
        record = self._records.get(record_id)
        return bool(record and record_id not in self._revoked and record["expires"] > time.time())

    def revoke(self, record_id: str) -> None:
        """Revoke a record so later lookups and status checks fail."""
        self._revoked.add(record_id)

    def expire(self, record_id: str) -> None:
        """Force a record's expiry into the past."""
        self._records[record_id]["expires"] = time.time() - 1

    def record_ids(self) -> tuple[str, ...]:
        """Return all known record identifiers, including inactive ones."""
        return tuple(self._records)

    def snapshot(self) -> list[dict[str, Any]]:
        """Return operator-visible copies of every local record and active flag."""
        return [
            {"record_id": record_id, "active": self.active(record_id), **copy.deepcopy(record)}
            for record_id, record in self._records.items()
        ]


class RPInterface:
    """Create RP requests and verify bound presentations.

    Audience, nonce, expiry and replay checks conceptually reflect federation
    verifier protections in [NIST63C]; no protocol conformance is claimed.
    """
    COMPONENT_NAME = "RP Interface"
    RAW_FIELDS = {"national_insurance_number", "country", "record_id", "subject"}
    REQUEST_FIELDS = {"id", "nonce", "rp_id", "purpose", "claim", "issued_at", "expires"}

    def __init__(self, rp_id: str, presentation_key: bytes, presentation_kid: str) -> None:
        """Create an RP with the shared presentation verification key."""
        self.rp_id = rp_id
        self._presentation_key = presentation_key
        self._presentation_kid = presentation_kid
        self._outstanding: dict[str, dict[str, Any]] = {}
        self._consumed_presentations: set[str] = set()
        self._consumed_requests: dict[tuple[str, str], dict[str, Any]] = {}

    def create_request(self, purpose: str, claim: str, ttl: int = 60) -> dict[str, Any]:
        """Mint a nonce-bound verification request with a limited lifetime."""
        issued_at = time.time()
        request = {
            "id": secrets.token_urlsafe(16),
            "nonce": secrets.token_urlsafe(16),
            "rp_id": self.rp_id,
            "purpose": purpose,
            "claim": claim,
            "issued_at": issued_at,
            "expires": issued_at + ttl,
        }
        self._outstanding[request["id"]] = copy.deepcopy(request)
        return request

    def receive(
        self,
        proof: dict[str, Any],
        request: dict[str, Any],
        trace: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Verify a presentation against an outstanding request and mint a receipt."""
        _require(request, self.REQUEST_FIELDS, "RP request")
        if request["rp_id"] != self.rp_id:
            raise ValueError("Request is for another RP")
        request_token = (str(request["id"]), str(request["nonce"]))
        consumed_request = self._consumed_requests.get(request_token)
        if consumed_request is not None and consumed_request != request:
            raise ValueError("Unknown or altered RP request")
        if consumed_request is None and self._outstanding.get(request["id"]) != request:
            raise ValueError("Unknown or altered RP request")
        payload = _open(
            self._presentation_key,
            CryptographicProofPresentationService.MESSAGE_TYPE,
            self._presentation_kid,
            proof,
        )
        _require(
            payload,
            CryptographicProofPresentationService.PAYLOAD_FIELDS,
            "derived presentation",
        )
        expected = (
            request["id"],
            request["nonce"],
            request["rp_id"],
            request["purpose"],
            request["claim"],
        )
        actual = tuple(
            payload.get(name)
            for name in ("request_id", "request_nonce", "rp_id", "purpose", "claim")
        )
        if actual != expected:
            raise ValueError("Proof has the wrong request, RP or purpose")
        if float(payload.get("expires", 0)) <= time.time():
            raise ValueError("Proof expired")
        if set(payload.get("statements", {})) != {request["claim"]}:
            raise ValueError("Derived statement missing")
        result = payload["statements"].get(request["claim"])
        if not isinstance(result, bool):
            raise ValueError("Derived statement missing")
        if consumed_request is not None:
            raise ValueError("RP request replay detected")
        if payload["jti"] in self._consumed_presentations:
            raise ValueError("Presentation replay detected")
        self._consumed_presentations.add(payload["jti"])
        self._consumed_requests[request_token] = copy.deepcopy(request)
        self._outstanding.pop(request["id"], None)
        _event(
            trace,
            self.COMPONENT_NAME,
            "presentation verification",
            "HMAC, request, RP, purpose, nonce and expiry valid",
        )
        return {
            "qualified": result,
            "proof": copy.deepcopy(proof),
            "payload": payload,
            "request": copy.deepcopy(request),
            "raw_attributes_received": bool(_all_keys(payload) & self.RAW_FIELDS),
            "verification": {
                "proof_hmac": True,
                "request_binding": True,
                "rp_binding": True,
                "purpose_binding": True,
                "nonce_binding": True,
                "not_expired": True,
                "replay_checked": True,
            },
        }


class AdminInterface:
    """Thin operator facade over management-plane trust administration."""
    COMPONENT_NAME = "Admin Interface"

    def __init__(self, management: ManagementPlane) -> None:
        """Attach to the management plane."""
        self.management = management

    def certify(
        self,
        provider_id: str,
        assertion_key: bytes,
        assertion_kid: str,
        status_key: bytes,
        status_kid: str,
        assurance: str = "substantial",
        validity_seconds: int = 3600,
    ) -> None:
        """Certify a provider's keys and assurance level via the management plane."""
        self.management.certify(
            provider_id,
            assertion_key,
            assertion_kid,
            status_key,
            status_kid,
            assurance,
            validity_seconds,
        )

    def suspend(self, provider_id: str) -> None:
        """Suspend a previously certified provider."""
        self.management.suspend(provider_id)

    def register_rp(self, rp_id: str, purposes: set[str], claims: set[str]) -> None:
        """Register permitted purpose/claim pairs for a relying party."""
        self.management.register_rp(rp_id, purposes, claims)


class ManagementPlane:
    """Applies trust changes to the registry and records them on the ledger."""
    COMPONENT_NAME = "Management Plane"

    def __init__(
        self,
        registry: TrustParticipantRegistry,
        ledger: TamperEvidentAssuranceLedger,
    ) -> None:
        """Bind registry updates to the tamper-evident assurance ledger."""
        self.registry = registry
        self.ledger = ledger

    def certify(
        self,
        provider_id: str,
        assertion_key: bytes,
        assertion_kid: str,
        status_key: bytes,
        status_kid: str,
        assurance: str,
        validity_seconds: int,
    ) -> None:
        """Certify a provider and append a ``provider_certified`` ledger event."""
        provider = self.registry.certify_provider(
            provider_id,
            assertion_key,
            assertion_kid,
            status_key,
            status_kid,
            assurance,
            validity_seconds,
        )
        self.ledger.append(
            "provider_certified",
            {
                "provider_id": provider_id,
                "key_id": assertion_kid,
                "assurance": assurance,
                "revision": provider["revision"],
            },
        )

    def suspend(self, provider_id: str) -> None:
        """Suspend a provider and append a ``provider_suspended`` ledger event."""
        revision = self.registry.suspend_provider(provider_id)
        self.ledger.append(
            "provider_suspended",
            {"provider_id": provider_id, "revision": revision},
        )

    def register_rp(self, rp_id: str, purposes: set[str], claims: set[str]) -> None:
        """Register RP permissions and append an ``rp_registered`` ledger event."""
        self.registry.set_rp(rp_id, purposes, claims)
        permitted_pairs = [
            {"purpose": purpose, "claim": claim}
            for purpose, claim in sorted(
                (purpose, claim) for purpose in purposes for claim in claims
            )
        ]
        self.ledger.append(
            "rp_registered",
            {"rp_id": rp_id, "permitted_pairs": permitted_pairs},
        )


class TrustParticipantRegistry:
    """Authoritative store of provider trust state and RP purpose/claim grants."""
    COMPONENT_NAME = "Trust/Participant Registry"

    def __init__(self) -> None:
        """Create empty provider and relying-party permission tables."""
        self._providers: dict[str, dict[str, Any]] = {}
        self._rps: dict[str, set[tuple[str, str]]] = {}

    def certify_provider(
        self,
        provider_id: str,
        assertion_key: bytes,
        assertion_kid: str,
        status_key: bytes,
        status_kid: str,
        assurance: str,
        validity_seconds: int,
    ) -> dict[str, Any]:
        """Publish or rotate a provider's trusted keys, assurance and validity."""
        if assurance not in ASSURANCE:
            raise ValueError("Unknown assurance level")
        now = time.time()
        revision = int(self._providers.get(provider_id, {}).get("revision", 0)) + 1
        self._providers[provider_id] = {
            "assertion_key": assertion_key,
            "status_key": status_key,
            "key_id": assertion_kid,
            "status_kid": status_kid,
            "assurance": assurance,
            "valid_from": now - 1,
            "valid_until": now + validity_seconds,
            "revision": revision,
            "certified": True,
        }
        return copy.deepcopy(self._providers[provider_id])

    def suspend_provider(self, provider_id: str) -> int:
        """Mark a provider uncertified and bump its trust revision."""
        if provider_id not in self._providers:
            raise ValueError(f"Unknown provider: {provider_id}")
        self._providers[provider_id]["certified"] = False
        self._providers[provider_id]["revision"] += 1
        return int(self._providers[provider_id]["revision"])

    def set_rp(self, rp_id: str, purposes: set[str], claims: set[str]) -> None:
        """Replace the permitted purpose/claim pairs for one relying party."""
        self._rps[rp_id] = {
            (purpose, claim) for purpose in purposes for claim in claims
        }

    def provider(self, provider_id: str, minimum_assurance: str) -> dict[str, Any]:
        """Return a currently trusted provider record meeting an assurance floor."""
        if provider_id not in self._providers:
            raise ValueError(f"Unknown provider: {provider_id}")
        if minimum_assurance not in ASSURANCE:
            raise ValueError("Unknown minimum assurance level")
        provider = self._providers[provider_id]
        now = time.time()
        if (
            not provider["certified"]
            or not provider["valid_from"] <= now < provider["valid_until"]
            or ASSURANCE[provider["assurance"]] < ASSURANCE[minimum_assurance]
        ):
            raise ValueError(f"Untrusted provider: {provider_id}")
        return copy.deepcopy(provider)

    def authorise(self, request: dict[str, Any]) -> dict[str, Any]:
        """Authorise an RP request against permissions and return the claim rule."""
        permissions = self._rps.get(request["rp_id"])
        if permissions is None or not any(
            purpose == request["purpose"] for purpose, _ in permissions
        ):
            raise ValueError("Purpose not allowed")
        if (request["purpose"], request["claim"]) not in permissions:
            raise ValueError("Claim not allowed")
        if request["claim"] not in RULES:
            raise _UnknownClaimError(request["claim"])
        return copy.deepcopy(RULES[request["claim"]])


class TamperEvidentAssuranceLedger:
    """Maintain a simplified HMAC-authenticated assurance-event hash chain.

    The design draws on secure audit-log principles [SK99] but provides no
    external anchoring, independent key custody or forward-integrity guarantee.
    """
    COMPONENT_NAME = "Tamper-Evident Assurance Ledger"
    ENTRY_TYPE = "ndi-assurance-ledger-entry-v1"
    ENTRY_FIELDS = {
        "sequence",
        "timestamp",
        "event",
        "data",
        "previous_hash",
        "hash",
        "audit_kid",
        "audit_tag",
    }

    def __init__(self, audit_key: bytes, audit_kid: str) -> None:
        """Create an empty ledger sealed by an audit HMAC key."""
        self._audit_key = audit_key
        self._audit_kid = audit_kid
        self._entries: list[dict[str, Any]] = []

    def append(self, event: str, data: dict[str, Any]) -> None:
        """Append one linked and HMAC-tagged assurance event."""
        previous = self._entries[-1]["hash"] if self._entries else "0" * 64
        entry = {
            "sequence": len(self._entries),
            "timestamp": time.time(),
            "event": event,
            "data": copy.deepcopy(data),
            "previous_hash": previous,
        }
        entry["hash"] = self._hash(entry)
        entry["audit_kid"] = self._audit_kid
        entry["audit_tag"] = self._audit_tag(self._audit_key, self._audit_kid, entry)
        self._entries.append(entry)

    @staticmethod
    def _hash(entry: dict[str, Any]) -> str:
        """Compute the SHA-256 content hash for one unsigned ledger entry."""
        unsigned = {
            name: entry[name]
            for name in ("sequence", "timestamp", "event", "data", "previous_hash")
        }
        return hashlib.sha256(_canonical(unsigned)).hexdigest()

    @staticmethod
    def _audit_tag(key: bytes, kid: str, entry: dict[str, Any]) -> str:
        """Compute the audit HMAC over a hashed ledger entry."""
        signed = {
            name: entry[name]
            for name in ("sequence", "timestamp", "event", "data", "previous_hash", "hash")
        }
        return _tag(key, TamperEvidentAssuranceLedger.ENTRY_TYPE, kid, signed)

    @classmethod
    def verify_entries(cls, entries: list[dict[str, Any]], key: bytes, kid: str) -> bool:
        """Validate sequence, hash links and audit tags for a list of entries."""
        previous = "0" * 64
        for sequence, entry in enumerate(entries):
            if not isinstance(entry, dict) or set(entry) != cls.ENTRY_FIELDS:
                return False
            if (
                entry.get("sequence") != sequence
                or entry.get("previous_hash") != previous
                or entry.get("audit_kid") != kid
                or entry.get("hash") != cls._hash(entry)
            ):
                return False
            expected_tag = cls._audit_tag(key, kid, entry)
            if not hmac.compare_digest(str(entry.get("audit_tag")), expected_tag):
                return False
            previous = str(entry["hash"])
        return True

    def valid(self) -> bool:
        """Return whether this ledger's in-memory entries currently authenticate."""
        return self.verify_entries(self._entries, self._audit_key, self._audit_kid)

    def snapshot(self) -> list[dict[str, Any]]:
        """Return a deep copy of every ledger entry."""
        return copy.deepcopy(self._entries)

    def save(self, path: Path) -> None:
        """Persist the entry list as indented JSON."""
        path.write_text(json.dumps(self._entries, indent=2), encoding="utf-8")

    @classmethod
    def load(
        cls,
        path: Path,
        audit_key: bytes,
        audit_kid: str,
    ) -> TamperEvidentAssuranceLedger:
        """Load a ledger instance from a JSON file without repairing mutations."""
        ledger = cls(audit_key, audit_kid)
        ledger._entries = json.loads(path.read_text(encoding="utf-8"))
        return ledger


class AuditorInterface:
    """Read, authenticate and pin ledger snapshots for the current run.

    The in-memory checkpoint can detect rollback only relative to an earlier
    observation in the same process; it cannot prove historical completeness.
    """
    COMPONENT_NAME = "Auditor Interface"

    def __init__(
        self,
        ledger: TamperEvidentAssuranceLedger,
        audit_key: bytes,
        audit_kid: str,
    ) -> None:
        """Attach to a ledger and prepare empty chain-head pins."""
        self._ledger = ledger
        self._audit_key = audit_key
        self._audit_kid = audit_kid
        self._last_count = 0
        self._last_head = "0" * 64

    def view(self) -> list[dict[str, Any]]:
        """Return the current ledger snapshot."""
        return self._ledger.snapshot()

    def verify_snapshot(self, entries: list[dict[str, Any]], pin: bool = False) -> bool:
        """Validate a snapshot and optionally pin its observed head."""
        if not TamperEvidentAssuranceLedger.verify_entries(
            entries, self._audit_key, self._audit_kid
        ):
            return False
        count = len(entries)
        head = entries[-1]["hash"] if entries else "0" * 64
        if count < self._last_count:
            return False
        if self._last_count and count > self._last_count:
            if entries[self._last_count - 1]["hash"] != self._last_head:
                return False
        if count == self._last_count and head != self._last_head:
            return False
        if pin:
            self._last_count, self._last_head = count, head
        return True

    def valid(self) -> bool:
        """Verify the live ledger and pin its head when successful."""
        return self.verify_snapshot(self.view(), pin=True)


# The fourteen Figure-3 public classes re-exported as this module's API surface.
PUBLIC_CLASSES = (
    UserInterface,
    HolderWallet,
    InclusionAssistedRoute,
    SchemeAccessCredentialService,
    NDISchemeGateway,
    CryptographicProofPresentationService,
    AssertionService,
    IdentityRegister,
    RPInterface,
    AdminInterface,
    ManagementPlane,
    TrustParticipantRegistry,
    TamperEvidentAssuranceLedger,
    AuditorInterface,
)
__all__ = tuple(item.__name__ for item in PUBLIC_CLASSES)


def _build() -> dict[str, Any]:
    """Build the demo using per-run keys and identifiers from [PY-SECRETS]."""
    access_key = secrets.token_bytes(32)
    presentation_key = secrets.token_bytes(32)
    subject_key = secrets.token_bytes(32)
    audit_key = secrets.token_bytes(32)
    ni_assertion_key = secrets.token_bytes(32)
    ni_status_key = secrets.token_bytes(32)
    residency_assertion_key = secrets.token_bytes(32)
    residency_status_key = secrets.token_bytes(32)

    ledger = TamperEvidentAssuranceLedger(audit_key, "audit-key-1")
    registry = TrustParticipantRegistry()
    management = ManagementPlane(registry, ledger)
    admin = AdminInterface(management)
    auditor = AuditorInterface(ledger, audit_key, "audit-key-1")

    ni_register = IdentityRegister(NI)
    ni_register.add("ada", national_insurance_number="QQ123")
    ni_register.add("ben", national_insurance_number="")
    residency_register = IdentityRegister(RESIDENCY)
    residency_register.add("ada", country="GB")
    residency_register.add("ben", country="GB")

    ni_assertions = AssertionService(
        NI,
        ni_register,
        ni_assertion_key,
        "ni-assertion-key-1",
        ni_status_key,
        "ni-status-key-1",
        subject_key,
    )
    residency_assertions = AssertionService(
        RESIDENCY,
        residency_register,
        residency_assertion_key,
        "residency-assertion-key-1",
        residency_status_key,
        "residency-status-key-1",
        subject_key,
    )
    proof_service = CryptographicProofPresentationService(
        {NI: ni_assertions, RESIDENCY: residency_assertions},
        presentation_key,
        "scheme-presentation-key-1",
    )
    admin.certify(
        NI,
        ni_assertion_key,
        "ni-assertion-key-1",
        ni_status_key,
        "ni-status-key-1",
    )
    admin.certify(
        RESIDENCY,
        residency_assertion_key,
        "residency-assertion-key-1",
        residency_status_key,
        "residency-status-key-1",
    )
    admin.register_rp(RP_ID, {"right_to_work_check"}, {"right_to_work_uk"})

    access = SchemeAccessCredentialService(access_key, "scheme-access-key-1")
    access.add_user("ada", "2468", {NI: "ada", RESIDENCY: "ada"})
    access.add_user("ben", "1357", {NI: "ben", RESIDENCY: "ben"})
    rp = RPInterface(RP_ID, presentation_key, "scheme-presentation-key-1")
    gateway = NDISchemeGateway(access, registry, proof_service, rp)
    wallet = HolderWallet(gateway)
    assisted = InclusionAssistedRoute(gateway)
    ui = UserInterface(wallet, assisted)

    return {
        UserInterface.COMPONENT_NAME: ui,
        HolderWallet.COMPONENT_NAME: wallet,
        InclusionAssistedRoute.COMPONENT_NAME: assisted,
        SchemeAccessCredentialService.COMPONENT_NAME: access,
        NDISchemeGateway.COMPONENT_NAME: gateway,
        CryptographicProofPresentationService.COMPONENT_NAME: proof_service,
        AssertionService.COMPONENT_NAME: (ni_assertions, residency_assertions),
        IdentityRegister.COMPONENT_NAME: (ni_register, residency_register),
        RPInterface.COMPONENT_NAME: rp,
        AdminInterface.COMPONENT_NAME: admin,
        ManagementPlane.COMPONENT_NAME: management,
        TrustParticipantRegistry.COMPONENT_NAME: registry,
        TamperEvidentAssuranceLedger.COMPONENT_NAME: ledger,
        AuditorInterface.COMPONENT_NAME: auditor,
    }


def _component(components: dict[str, Any], cls: type) -> Any:
    """Fetch one built component instance by class."""
    return components[cls.COMPONENT_NAME]


def _clear_screen() -> None:
    """Clear the interactive terminal when stdout is a TTY."""
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def _show_records(components: dict[str, Any]) -> None:
    """Print synthetic provider databases without sending them to the RP."""
    registers = _component(components, IdentityRegister)
    print("PROVIDER DATABASES")
    print("Synthetic provider records; these are not sent to the relying party.")
    for register in registers:
        print(f"\n{register.provider_id}")
        for record in register.snapshot():
            attributes = {
                key: value
                for key, value in record.items()
                if key not in {"record_id", "subject", "expires", "active"}
            }
            rendered = ", ".join(
                f"{key}={value if value not in ('', None) else '<missing>'}"
                for key, value in attributes.items()
            )
            print(
                f"  {record['record_id']}: {rendered}; "
                f"active={'yes' if record['active'] else 'no'}"
            )
    print("\nBoundary: the raw records remain inside their provider components.")


def _run_check(components: dict[str, Any]) -> dict[str, Any] | None:
    """Prompt for Ada/Ben, run a wallet check and print a concise result."""
    print("RIGHT-TO-WORK CHECK")
    print("1. Ada (PIN 2468)")
    print("2. Ben (PIN 1357)")
    choice = input("Person: ").strip()
    username = {"1": "ada", "2": "ben"}.get(choice)
    person = {"1": "Ada", "2": "Ben"}.get(choice)
    if username is None:
        print("Choose 1 or 2.")
        return None
    pin = (
        getpass.getpass("PIN: ").strip()
        if sys.stdin.isatty()
        else input("PIN: ").strip()
    )
    trace: list[dict[str, str]] = []
    try:
        receipt = _component(components, UserInterface).check(username, pin, trace=trace)
    except ValueError as exc:
        _clear_screen()
        print("RIGHT-TO-WORK CHECK RESULT")
        print(f"Person: {person}")
        print("Login: INVALID" if str(exc) == "Sign-in failed" else f"Check: FAILED - {exc}")
        return None
    local_checks = [
        event
        for event in trace
        if event["component"].startswith(AssertionService.COMPONENT_NAME)
        and event["action"] == "local check"
    ]
    values = ["=True" in event["result"] for event in local_checks]
    if len(values) != 2:
        raise RuntimeError("Expected two provider-local Boolean checks")
    ni_result = "PASS" if values[0] else "FAIL"
    residency_result = "PASS" if values[1] else "FAIL"
    derived_result = "PASS" if receipt["qualified"] else "FAIL"
    _clear_screen()
    print("RIGHT-TO-WORK CHECK RESULT")
    print(f"Person: {person}")
    print("Login: VALID")
    print(f"\nNational Insurance check: {ni_result}")
    print(f"UK residency check: {residency_result}")
    print(f"Derived result: {ni_result} AND {residency_result} = {derived_result}")
    print(
        "\nRP received: Right-to-work eligibility = "
        f"{str(receipt['qualified']).upper()}"
    )
    print(
        "Raw provider attributes disclosed: "
        f"{'YES' if receipt['raw_attributes_received'] else 'NO'}"
    )
    print("Authenticated presentation: VALID")
    return receipt


def _show_payload(receipt: dict[str, Any] | None) -> None:
    """Print the last successful authenticated RP presentation, if any."""
    if receipt is None:
        print("LAST SUCCESSFUL RP PRESENTATION")
        print("No presentation is available. Run option 2 successfully first.")
        return
    payload = receipt["payload"]
    verification = receipt["verification"]
    provider_names = {
        NI: "National Insurance",
        RESIDENCY: "UK Residency",
    }
    check_names = {
        "has_nino": "NI-number presence check",
        "uk_resident": "UK-residency check",
    }
    bindings_valid = all(
        verification.get(name) is True
        for name in (
            "request_binding",
            "rp_binding",
            "purpose_binding",
            "nonce_binding",
        )
    )
    expires = time.strftime(
        "%Y-%m-%d %H:%M:%S UTC", time.gmtime(payload["expires"])
    )
    print("LAST SUCCESSFUL RP PRESENTATION")
    print("Relying party: Example Employer")
    print("Purpose: Right-to-work eligibility check")
    print(
        "Derived result: Right-to-work eligibility = "
        f"{str(receipt['qualified']).upper()}"
    )

    print("\nPROVIDER EVIDENCE")
    for provider_id, source in payload["sources"].items():
        provider = provider_names.get(provider_id, provider_id)
        check = check_names.get(source["check"], source["check"])
        print(f"- {provider}: {check}")
    print(
        f"Verified sources: {verification['sources_verified']}/{len(payload['sources'])} | "
        f"Fresh status: {verification['fresh_status']}/{len(payload['sources'])}"
    )

    print("\nVERIFICATION")
    print(f"Authentication: {'VALID' if verification['proof_hmac'] else 'INVALID'}")
    print(
        "Bindings (request, RP, purpose and nonce): "
        f"{'VALID' if bindings_valid else 'INVALID'}"
    )
    print(
        f"Policy rechecked: {'YES' if verification['policy_rechecked'] else 'NO'} | "
        f"Replay check: {'PASSED' if verification['replay_checked'] else 'FAILED'}"
    )
    print(f"Accepted before expiry: {'YES' if verification['not_expired'] else 'NO'}")
    print(f"Expires: {expires}")

    print("\nDATA RELEASE")
    print(
        "Raw provider attributes: "
        f"{'PRESENT' if receipt['raw_attributes_received'] else 'NONE'}"
    )
    print(f"Provider-local trace: {'PRESENT' if 'trace' in payload else 'NONE'}")
    print("Scope: synthetic result; not a statutory right-to-work decision.")


def _show_audit(components: dict[str, Any]) -> None:
    """Print the chronological human-readable assurance audit log."""
    auditor = _component(components, AuditorInterface)
    entries = auditor.view()
    verified = auditor.verify_snapshot(entries)
    provider_names = {
        NI: "National Insurance",
        RESIDENCY: "UK Residency",
    }
    rp_names = {RP_ID: "Example Employer"}
    print("AUDIT LOG")
    print("Scheme trust changes. No resident records or eligibility results.")
    print(f"Snapshot authentication: {'PASS' if verified else 'FAIL'}")
    if not verified:
        print("Event details are hidden because this snapshot is not trusted.")
        return
    print()
    for entry in entries:
        data = entry["data"]
        number = entry["sequence"] + 1
        timestamp = time.strftime(
            "%Y-%m-%d %H:%M:%S UTC", time.gmtime(entry["timestamp"])
        )
        if entry["event"] == "provider_certified":
            provider_id = data["provider_id"]
            detail = f"Provider certified: {provider_names.get(provider_id, provider_id)}"
            metadata = (
                f"provider_id={provider_id} | assurance={data['assurance']} | "
                f"revision={data['revision']} | key_id={data['key_id']}"
            )
        elif entry["event"] == "provider_suspended":
            provider_id = data["provider_id"]
            detail = f"Provider suspended: {provider_names.get(provider_id, provider_id)}"
            metadata = f"provider_id={provider_id} | revision={data['revision']}"
        elif entry["event"] == "rp_registered":
            rp_id = data["rp_id"]
            detail = f"Relying party registered: {rp_names.get(rp_id, rp_id)}"
            permitted = ", ".join(
                f"{pair['purpose']} -> {pair['claim']}"
                for pair in data["permitted_pairs"]
            )
            metadata = f"rp_id={rp_id} | permitted={permitted or '<none>'}"
        else:
            detail = entry["event"].replace("_", " ").title()
            metadata = ""
        print(f"{number:03d} | {timestamp} | {detail}")
        if metadata:
            print(f"      {metadata}")

    print(f"\nEvents recorded: {len(entries)}")


def _show_ledger(components: dict[str, Any]) -> None:
    """Print the read-only integrity view of the tamper-evident ledger."""
    auditor = _component(components, AuditorInterface)
    entries = auditor.view()
    valid = auditor.valid()
    labels = [
        str(entry["sequence"] + 1)
        if isinstance(entry, dict)
        and isinstance(entry.get("sequence"), int)
        and not isinstance(entry.get("sequence"), bool)
        else "?"
        for entry in entries
    ]
    sequence = " -> ".join(["START", *labels])
    checkpoint = f"ENTRY {labels[-1]}" if labels else "EMPTY LEDGER"
    print("TAMPER-EVIDENT LEDGER")
    print("READ-ONLY LEDGER VIEW")
    print(f"\nStored entry sequence: {sequence}")
    print(f"Entries checked: {len(entries)}")
    print(
        "Verification: "
        + (
            "PASS - the current snapshot's order, SHA-256 links and HMAC tags authenticate."
            if valid
            else "FAIL - the current snapshot did not authenticate."
        )
    )
    print(
        f"Run-local checkpoint: {'VERIFIED AT ' + checkpoint if valid else 'NOT UPDATED'}"
    )
    print(f"Status: {'AUTHENTICATED CURRENT SNAPSHOT' if valid else 'INVALID SNAPSHOT'}")


def _menu(components: dict[str, Any]) -> None:
    """Run the interactive operator menu until the user exits."""
    last_receipt: dict[str, Any] | None = None
    _clear_screen()
    print("Synthetic federated right-to-work demonstrator")
    while True:
        print(
            "\n1 records | 2 check | 3 RP presentation | "
            "4 audit log | 5 tamper-evident ledger | 0 exit"
        )
        try:
            choice = input("Choice: ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "0"
        if choice == "0":
            print("Demo closed.")
            return
        if choice in {"1", "2", "3", "4", "5"}:
            _clear_screen()
        if choice == "1":
            _show_records(components)
        elif choice == "2":
            receipt = _run_check(components)
            if receipt is not None:
                last_receipt = receipt
        elif choice == "3":
            _show_payload(last_receipt)
        elif choice == "4":
            _show_audit(components)
        elif choice == "5":
            _show_ledger(components)
        else:
            print("Choose 0 to 5.")


if __name__ == "__main__":
    _menu(_build())
