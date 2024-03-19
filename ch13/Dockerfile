FROM python:3.10.6-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Create and set the working directory
RUN mkdir -p /orders/orders
WORKDIR /orders

# Install system dependencies
RUN apt-get update \
    && apt-get install -y libpq-dev \
    && apt-get install -y gcc

# Install Pipenv and project dependencies
RUN pip install -U pip && pip install pipenv
COPY Pipfile Pipfile.lock /orders/
RUN pipenv install --system --deploy

# Copy project files
COPY orders/orders_service /orders/orders/orders_service/
COPY orders/repository /orders/orders/repository/
COPY orders/web /orders/orders/web/
COPY oas.yaml /orders/
COPY alembic.ini /orders/
COPY migrations /orders/migrations
COPY public_key.pem /orders/public_key.pem
COPY private_key.pem /orders/private_key.pem

# Expose the necessary port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "orders.web.app:app", "--host", "0.0.0.0"]
