-- One database per service, so no service can read another's tables by accident.
CREATE DATABASE auth;
CREATE DATABASE resources;
