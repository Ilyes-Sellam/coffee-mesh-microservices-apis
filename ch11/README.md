## Activate the virtual environment by running:
* `$ pipenv shell`


## Start the server with the following command:
* `$ AUTH_ON=True uvicorn orders.web.app:app --reload`

## Run the following command to create the new Alembic migration:
* `$ PYTHONPATH=``pwd`` alembic revision --autogenerate -m "Add user id to order table"`

## We run the migration with the following command:
* `$ PYTHONPATH=``pwd`` alembic upgrade heads`