"""Coverage-guided fuzzing (Atheris) of the Hypothesis properties in
tests/test_properties.py: libFuzzer feeds each property's
`.hypothesis.fuzz_one_input`, so a fuzzer finding is a failing property.

Atheris only has Linux x86_64 wheels (see the `fuzz` group in pyproject.toml):

    uv sync --group fuzz
    uv run python fuzz/fuzz_properties.py <target> [libFuzzer flags]
    uv run python fuzz/fuzz_properties.py <target> <crash-file>   # replay a finding
"""

import sys
from pathlib import Path

import atheris
from hypothesis import settings

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Registered before the tests are imported so their @settings inherit it: the
# fuzzer owns the inputs and the time budget, so no example database or deadline.
settings.register_profile("fuzz", deadline=None, database=None)
settings.load_profile("fuzz")

# Every property except the vault round-trip, whose key derivations make each
# input too slow to be worth fuzzing (its tampering check needs no fuzzer).
TARGETS = {
    "scrub_text": "test_scrub_text_never_raises",
    "scrub_long_secrets": "test_long_secrets_never_survive_scrubbing",
    "scrub_short_secrets": "test_short_secrets_never_survive_as_whole_words",
    "scrub_idempotent": "test_scrub_text_is_idempotent",
    "scrub_event_leaks": "test_scrub_event_leaks_no_secret_in_keys_or_values_and_drops_nothing",
    "scrub_event_fail_closed": "test_scrub_event_never_hits_the_fail_closed_path",
    "collect_secrets": "test_collect_secrets_never_raises_on_any_playbook_text",
    "vault_decrypt": "test_decrypt_raises_only_vault_error",
    "vault_encrypt": "test_encrypt_raises_only_vault_error",
    "inventory_render": "test_rendered_inventory_parses_back_to_exactly_the_input",
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in TARGETS:
        sys.exit(f"usage: {sys.argv[0]} <target> [libFuzzer flags]\ntargets: {', '.join(TARGETS)}")
    target = sys.argv.pop(1)

    # The parsers the properties feed are guidance too: with only `app`
    # instrumented, the fuzzer can't tell one YAML document from another.
    with atheris.instrument_imports(include=["app", "yaml", "ansible.parsing"]):
        from tests import test_properties

    prop = getattr(test_properties, TARGETS[target])
    atheris.Setup(sys.argv, prop.hypothesis.fuzz_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
