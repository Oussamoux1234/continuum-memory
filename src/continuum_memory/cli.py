"""User-control CLI. Administrative actions always render and confirm an exact preview."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from . import __version__
from .broker import TerminalApprovalBroker
from .client import DaemonClient
from .daemon import _default_home
from .errors import MemoryError
from .security import (
    MAX_BODY_BYTES,
    MAX_SUBJECT_BYTES,
    absolute_path,
    bounded_provider,
    bounded_text,
    canonical_json,
)
from .storage import Store, paths


def _client(data_dir: Path) -> DaemonClient:
    return DaemonClient(data_dir, paths(data_dir)["control"])


def _print(value: Any, compact: bool) -> None:
    if compact:
        print(canonical_json(value))
    else:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _admin(client: DaemonClient, params: Dict[str, Any]) -> Dict[str, Any]:
    challenge = client.call("admin_preview", params)
    broker = TerminalApprovalBroker(client.data_dir / "control.cap")
    grant = broker.authorize(challenge)
    return client.call(
        "admin_apply",
        {
            "nonce": challenge["nonce"],
            "preview_digest": challenge["preview_digest"],
            "grant": grant,
            "preview": challenge["preview"],
        },
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="continuum", description="Continuum Memory prototype CLI")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--data-dir", type=Path, default=_default_home())
    parser.add_argument("--json", action="store_true", help="emit compact JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("--project-name", required=True)
    init.add_argument("--project-path", required=True, type=Path)
    init.add_argument("--providers", default="codex,claude")

    remember = sub.add_parser("remember")
    _project(remember)
    remember.add_argument("--subject", required=True)
    remember.add_argument("--claim", required=True)
    remember.add_argument("--evidence", default="")
    remember.add_argument("--evidence-locator", default="user:terminal")
    _policy_args(remember)
    _valid_args(remember)

    inbox = sub.add_parser("inbox")
    _project(inbox)
    inbox.add_argument("--status", choices=["proposed", "accepted", "rejected"], default="proposed")
    inbox.add_argument("--limit", type=int, default=5)

    review = sub.add_parser("review")
    _project(review)
    review.add_argument("proposal_id")
    choice = review.add_mutually_exclusive_group(required=True)
    choice.add_argument("--accept", action="store_true")
    choice.add_argument("--reject", action="store_true")

    search = sub.add_parser("search")
    _project(search)
    search.add_argument("--query", required=True)
    search.add_argument("--limit", type=int, default=10)
    _query_temporal(search)

    context = sub.add_parser("context")
    _project(context)
    context.add_argument("--query", required=True)
    context.add_argument("--max-tokens", type=int, default=1024)
    context.add_argument("--max-bytes", type=int, default=8192)
    _query_temporal(context)

    show = sub.add_parser("show")
    _project(show)
    show.add_argument("id")
    show.add_argument("--history", action="store_true")

    correct = sub.add_parser("correct")
    _project(correct)
    correct.add_argument("target_id")
    correct.add_argument("--claim", required=True)
    correct.add_argument("--evidence", default="User correction")
    correct.add_argument("--evidence-locator", default="user:correction")

    forget = sub.add_parser("forget")
    _project(forget)
    forget.add_argument("target_id")

    status = sub.add_parser("status")
    status.add_argument("--project", required=True)

    audit = sub.add_parser("audit")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_sub.add_parser("verify")
    return parser


def _project(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", required=True)


def _policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--classification", choices=["public", "internal", "confidential", "restricted"], default="internal")
    parser.add_argument("--retention", default="forever")
    parser.add_argument("--disclosure", default="*", help="comma-separated providers or *")


def _valid_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--valid-precision", choices=["unknown", "instant", "open", "interval"], default="unknown")
    parser.add_argument("--valid-from")
    parser.add_argument("--valid-to")


def _query_temporal(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--temporal-mode", choices=["current", "history"], default="current")
    parser.add_argument("--as-of-recorded", type=int)
    parser.add_argument("--as-of-valid")


def _clean(value: Dict[str, Any]) -> Dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}


def run(args: argparse.Namespace) -> Any:
    data_dir = absolute_path(args.data_dir)
    if args.command == "init":
        name = bounded_text(args.project_name, "project_name", MAX_SUBJECT_BYTES)
        providers = [bounded_provider(item.strip()) for item in args.providers.split(",") if item.strip()]
        if not providers:
            raise MemoryError("invalid_request", "At least one provider is required.")
        path_hint = str(args.project_path.resolve())
        bounded_text(path_hint, "project_path", MAX_BODY_BYTES)
        return Store.bootstrap(data_dir, [{"name": name, "path_hint": path_hint, "providers": providers}])
    client = _client(data_dir)
    if args.command == "remember":
        return _admin(
            client,
            _clean(
                {
                    "operation": "remember",
                    "project": args.project,
                    "subject": args.subject,
                    "claim": args.claim,
                    "evidence": args.evidence,
                    "evidence_locator": args.evidence_locator,
                    "classification": args.classification,
                    "retention": args.retention,
                    "disclosure": [item.strip() for item in args.disclosure.split(",")],
                    "valid_precision": args.valid_precision,
                    "valid_from": args.valid_from,
                    "valid_to": args.valid_to,
                }
            ),
        )
    if args.command == "inbox":
        return client.call("inbox", {"project": args.project, "status": args.status, "limit": args.limit})
    if args.command == "review":
        operation = "accept_proposal" if args.accept else "reject_proposal"
        return _admin(client, {"operation": operation, "project": args.project, "proposal_id": args.proposal_id})
    if args.command == "search":
        return client.call(
            "search",
            _clean(
                {
                    "project": args.project,
                    "query": args.query,
                    "limit": args.limit,
                    "temporal_mode": args.temporal_mode,
                    "as_of_recorded": args.as_of_recorded,
                    "as_of_valid": args.as_of_valid,
                }
            ),
        )
    if args.command == "context":
        return client.call(
            "context",
            _clean(
                {
                    "project": args.project,
                    "query": args.query,
                    "max_tokens": args.max_tokens,
                    "max_bytes": args.max_bytes,
                    "temporal_mode": args.temporal_mode,
                    "as_of_recorded": args.as_of_recorded,
                    "as_of_valid": args.as_of_valid,
                }
            ),
        )
    if args.command == "show":
        return client.call("show", {"project": args.project, "id": args.id, "history": args.history})
    if args.command == "correct":
        return _admin(
            client,
            {
                "operation": "correct",
                "project": args.project,
                "target_id": args.target_id,
                "claim": args.claim,
                "evidence": args.evidence,
                "evidence_locator": args.evidence_locator,
            },
        )
    if args.command == "forget":
        return _admin(client, {"operation": "forget", "project": args.project, "target_id": args.target_id})
    if args.command == "status":
        return client.call("status", {"project": args.project})
    if args.command == "audit" and args.audit_command == "verify":
        return client.call("audit_verify", {})
    raise MemoryError("invalid_request", "No command was selected.")


def main(argv: Any = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = run(args)
        _print(result, args.json)
        return 0
    except MemoryError as exc:
        _print({"error": exc.as_dict()}, True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
