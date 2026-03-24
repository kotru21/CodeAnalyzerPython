// Safe: JSON.parse with schema validation
const data = JSON.parse(req.body.json);
const validated = schema.validate(data);
