# syntax=docker/dockerfile:1
# Use an official Python runtime as a base image
FROM python:3.13

# Set the working directory in the container
WORKDIR /usr/local/app

COPY app/ ./

# Document that the container listens on port 8080
EXPOSE 8000

# Runtime instructions
CMD ["python", "app.py"]