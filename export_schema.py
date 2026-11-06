import json
from preflight.models import Policy

schema = Policy.model_json_schema()
with open("policy.schema.json", "w") as f:
    json.dump(schema, f, indent=2)