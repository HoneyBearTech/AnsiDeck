"""The run worker (python -m app.worker): claims queued runs from the API's internal API and
executes them. It never touches the database or the encryption key: the API hands it each
job's secrets once, and it scrubs output with them before sending it back.

Only app.worker.*, app.run_executor, app.scrub (with app.vault), app.subprocess_env and
app.process_hardening may be imported here (a test enforces it): in particular never
app.config, which would load the API's settings and secrets.
"""
