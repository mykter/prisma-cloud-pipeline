"""Retrieve container findings from Prisma Cloud and apply local triage rules

Can be used as a library or a CLI"""

import os
import json
import jsonschema  # type: ignore

# a validator for the triage rules.
with open(os.path.join(os.path.split(__file__)[0], "rules-schema.json")) as schema:
    rules_validator = jsonschema.Draft7Validator(json.load(schema))
