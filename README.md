# One Time command
poetry config virtualenvs.in-project true

# Step1:
poetry shell
(to activate the virtualenv)

# step2:
poetry lock --no-update && poetry install --no-root
(to install the modules & dependencies)