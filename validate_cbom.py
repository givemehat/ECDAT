"""Validate an emitted CBOM against the published CycloneDX 1.7 JSON Schema.

The previous validate_real_world.py printed "Skipping schema validation due to 404 on schema
URL" -- i.e. the document was never actually checked. This does the check, offline, against a
schema fetched once and cached in the repository (schemas/bom-1.7.schema.json).

    python validate_cbom.py indramesh_report.json [schemas/bom-1.7.schema.json]
Exit code 0 = valid, 1 = invalid, 2 = schema unavailable.
"""
import json
import os
import sys

DEFAULT_SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "schemas", "bom-1.7.schema.json")
SCHEMA_URL = ("https://raw.githubusercontent.com/CycloneDX/specification/"
              "master/schema/bom-1.7.schema.json")


def validate(cbom_path, schema_path=DEFAULT_SCHEMA):
    try:
        import jsonschema
    except ImportError:
        print("[!] jsonschema is not installed. Run:  pip install jsonschema")
        return 2

    if not os.path.exists(schema_path):
        print(f"[!] Schema not found at {schema_path}")
        print(f"    Fetch it with:\n      curl -o {schema_path} {SCHEMA_URL}")
        return 2

    with open(schema_path, encoding="utf-8") as fh:
        schema = json.load(fh)
    with open(cbom_path, encoding="utf-8") as fh:
        document = json.load(fh)

    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))

    if not errors:
        print(f"[+] VALID against CycloneDX {document.get('specVersion')} schema")
        print(f"    {len(document.get('components', []))} component(s) checked")
        return 0

    print(f"[x] INVALID against CycloneDX {document.get('specVersion')} schema "
          f"({len(errors)} error(s)):")
    for err in errors[:20]:
        path = "/".join(str(p) for p in err.absolute_path) or "<root>"
        print(f"  - {path}: {err.message[:220]}")
    if len(errors) > 20:
        print(f"  ... and {len(errors) - 20} more")
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(validate(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else DEFAULT_SCHEMA))
