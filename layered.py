from datetime import datetime
from typing import Any
from dataclasses import dataclass, asdict, field

import orjson


###############################################################################
# ERRORS
###############################################################################


class ServiceError(Exception):
    """Base exception for service.

    This allow to catch service specific errors all the way up to top layer.
    """


class UserServiceError(ServiceError):
    """Special exception for User part of layer.

    This mean, that every entity will have it's own exception.

    it is usefull to mention in all User layers.
    """


###############################################################################
# MODELS
###############################################################################


@dataclass
class UserModel:
    id: int
    name: str
    email: str


###############################################################################
# DATA ACCESS LAYER
#
# /!\ all DAL's are singletons for simplicity purpose /!\
#
# Those classes incapsulates ONLY technical details of how data is stored
#
###############################################################################


UserT = dict[str, int | str]


@dataclass(eq=False, frozen=True, slots=True)
class Cache:
    """Mock for Redis.

    * get simple data input (dict to store and int/str to get)
    * do not raise any ServiceException
    * if data not found may return None or raise- both are ok here
    * return simple data as dict
    """

    cache: dict[str, bytes] = field(default_factory=dict)

    @staticmethod
    def get_user_key(user_id: int) -> str:
        return f"user_id:{user_id}"

    def get_user_by_id(self, user_id: int) -> UserT | None:
        key = self.get_user_key(user_id)
        if user_str := self.cache.get(key):
            return orjson.loads(user_str)
        return None

    def set_user_by_id(self, user: UserT, user_id: int) -> None:
        key = self.get_user_key(user_id)
        self.cache[key] = orjson.dumps(user)

    def invalidate_user_by_id(self, user_id: int) -> None:
        key = self.get_user_key(user_id)
        self.cache.pop(key, None)


@dataclass(eq=False, frozen=True, slots=True)
class DB:
    """Mock for postgres.

    * get simple data input (dict to store and int/str to get)
    * do not raise any ServiceException
    * if data not found may return None or raise- both are ok here
    * return simple data as dict or Record
    """

    users: list[UserT] = field(default_factory=list)

    @property
    def user_email_uindex(self) -> set[str]:
        return {str(user["email"]) for user in self.users}

    def get_user_by_id(self, user_id: int) -> UserT | None:
        """Mimic PG: return Record or None"""
        # actually this happen:
        # select * from users where user_id = $1
        # and it may return None
        for user in self.users:
            if user["id"] == user_id:
                return user
        return None

    def create_user(self, name: str, email: str) -> UserT:
        """Mimic PG: return int or raise"""
        # actually this happen:
        # insert into users ( name, email ) values ( $1, $2 ) returning id
        if email in self.user_email_uindex:
            # UniqueViolationError
            raise UserServiceError("user email already registered")
        user_id = len(self.users)
        user: UserT = {"id": user_id, "name": name, "email": email}
        self.users.append(user)
        return user

    def update_user_by_id(
        self, user_id: int, *, name: str | None, email: str | None
    ) -> UserT:
        user = self.get_user_by_id(user_id)
        if user is None:
            raise UserServiceError("user not found")
        if email:
            if email in self.user_email_uindex:
                # UniqueViolationError
                raise UserServiceError("email already registered")
            user["email"] = email
        if name:
            user["name"] = name
        return user


###############################################################################
# DATA ACCESS LAYER
# a.k.a.
# the Repository
#
# Incapsulates storage logic
# * get arguments as simple data
# * get raw data from storage
# * create Model from raw data
# * return Model
# * Model is immutable
# * update entities by id/field and kwargs
# in case of error always raise exception inherited from DALError
# if data not found will raise error.
#
# Why not to return empty value if operation is not complete?
# Isn't that more pythonic way?
# Sometimes we need to pass through no only fact of error, e.x. user not
# created or user not found. We need to pass upwards the cause of error- why
# user can not be created. Maybe email is already registered, or maybe
# database did not respond. Same for user- why it is not found.
# Thats why we may use 2 options:
# 1- use Go-like notation and always return tuple of value and error
# 2- throw exceptions of something went wrong
# But we do not want to throw any exception, because catching general Exception
# is usually a bad practice. We need to specify special base exception and
# raise it or it's children with specific info about error. This may help us
# to properly handle them.
#
###############################################################################


@dataclass(eq=False, frozen=True, slots=True)
class UserRepository:
    """Get and set data from here. All data access are hidden here.

    * get arguments as simple data
    * return Model or raise RepositoryError
    """

    db: DB = field(default_factory=DB)
    cache: Cache = field(default_factory=Cache)

    def get_user_by_id(self, user_id: int) -> UserModel:
        if user := self.cache.get_user_by_id(user_id):
            return UserModel(**user)
        if user := self.db.get_user_by_id(user_id):
            self.cache.set_user_by_id(user, user_id)
            return UserModel(**user)
        raise UserServiceError("user not found")

    def create_user(self, name: str, email: str) -> UserModel:
        user_id: int = self.db.create_user(name, email)
        return UserModel(user_id, name, email)

    def update_user_by_id(
        self, user_id: int, *, name: str | None, email: str | None
    ) -> UserModel:
        if not any([name, email]):
            raise UserServiceError("nothing to update")
        # prevent race condition by first update then invalidate
        user = self.db.update_user_by_id(user_id, name=name, email=email)
        self.cache.invalidate_user_by_id(user_id)
        return UserModel(**user)


###############################################################################
# Clents
#
# Stuff, you usually want to call inside business layer.
###############################################################################


class Notifier:
    def notify_user(self, user: UserModel, message: str) -> None:
        msg = f"EMAIL: {user.email} MESSAGE: 'Hello, {user.name}! {message}'"
        print(msg)


class Databus:
    def send_user_registered_message(self, user: UserModel) -> None:
        msg = f"DATABUS: event: UserRegistered {asdict(user)}"
        print(msg)


class Clickstream:
    def send_user_registered_event(self, user: UserModel) -> None:
        event = {
            "eid": "user_register",
            "user_id": user.id,
            "user_name": user.name,
            "user_email": user.email,
            "timestamp": datetime.now().isoformat(),
        }
        msg = f"CLICKSTREAM: {event}"
        print(msg)


###############################################################################
# SERVICE LAYER
# a.k.a.
# DOMAIN LAYER
# a.k.a.
# BUSINESS LOGIC LAYER
#
# this layer contain application business logic
# it uses Data Access Layer to communicate with databases:
# * to get data
# * to create data
# * to update data
#
# any errors always cause to raise an exception inheritd from base exception
###############################################################################


@dataclass(eq=False, frozen=True, slots=True)
class UserService:
    """Business logic for User entity goes here.

    * inputs may be any: simple or dto or model
    * in case of error always raise exception inherited from ServiceError
    """

    repo: UserRepository = field(default_factory=UserRepository)
    notifier: Notifier = field(default_factory=Notifier)
    databus: Databus = field(default_factory=Databus)
    clickstream: Clickstream = field(default_factory=Clickstream)

    def get_user_by_id(self, user_id: int) -> UserModel:
        """raises: UserServiceError"""
        return self.repo.get_user_by_id(user_id)

    def create_user(self, name: str, email: str) -> UserModel:
        """raises: UserServiceError"""
        user = self.repo.create_user(name, email)
        self.notifier.notify_user(user, "You are registered.")
        self.databus.send_user_registered_message(user)
        self.clickstream.send_user_registered_event(user)
        return user

    def update_user(
        self, user_id: int, *, name: str | None, email: str | None
    ) -> UserModel:
        """raises: UserServiceError"""
        user = self.repo.update_user_by_id(user_id, name=name, email=email)
        self.notifier.notify_user(user, "Your account is updated.")
        return user


###############################################################################
# PRESENTATION LAYER
# a.k.a.
# HTTP Layer
#
# This layer handle input data and output data. In Hexagonal architecture,
# this layer is split between two adaptors- one for input, one for output.
# But we may di everything in one place, because there is no real reason
# (at least for now) to, for example, receive HTTP request and print out
# data to CLI. If we would like to send HTTP requests from CLI, then we may
# definitely split.
#
# This layer:
# * validate input data
# * create all required objects for next layers
# * call 1 method of each object
# * contain NO BUSINESS LOGIC AT ALL <- this is crucial
# * capture possible Service layer errors
# * encode result into appropriate format (json, xml)
#
###############################################################################


@dataclass(eq=False, frozen=True, slots=True)
class Handler:
    user_service: UserService = field(default_factory=UserService)


class CreateUserHandler(Handler):
    def validate_payload(self, payload: dict) -> str | None:
        """Validate input."""
        if "name" not in payload:
            return "name required"
        name = payload["name"]
        if not isinstance(name, str):
            return "name must be str"
        if len(name) < 3:
            return "name must at least 3 chars long"
        if "email" not in payload:
            return "email required"
        email = payload["email"]
        if not isinstance(email, str):
            return "email must be str"
        if "@" not in email:
            return "invalid email format"
        return None

    def post(self, payload: dict[str, Any]) -> dict[str, Any]:
        if error := self.validate_payload(payload):
            return {"error": error}
        name = payload["name"]
        email = payload["email"]
        try:
            user = self.user_service.create_user(name=name, email=email)
        except UserServiceError as err:
            return {"error": str(err)}
        if not user:
            return {"error": "unknown error"}
        return {"user": asdict(user)}


class GetUserHandler(Handler):
    def validate_payload(self, payload: dict) -> str | None:
        """Validate input."""
        user_id = payload.get("id")
        if user_id is None:
            return "user_id required"
        if not isinstance(user_id, int):
            return "user_id must be int"
        if user_id < 0:
            return "user_id invalid"
        return None

    def post(self, payload: dict[str, Any]) -> dict[str, Any]:
        if error := self.validate_payload(payload):
            return {"error": error}
        user_id = payload["id"]
        try:
            user = self.user_service.get_user_by_id(user_id)
        except UserServiceError as err:
            return {"error": str(err)}
        return {"user": asdict(user)}


class UpdateUserHandler(Handler):
    def validate_payload(self, payload: dict) -> str | None:
        """Validate input."""
        user_id = payload.get("id")
        if user_id is None:
            return "user_id required"
        if not isinstance(user_id, int):
            return "user_id must be int"
        if user_id < 0:
            return "user_id invalid"
        if "name" not in payload and "email" not in payload:
            return "'name' or 'email' is required"
        if name := payload.get("name"):
            if not isinstance(name, str):
                return "name must be str"
            if len(name) < 3:
                return "name must at least 3 chars long"
        if email := payload.get("email"):
            if not isinstance(email, str):
                return "email must be str"
            if "@" not in email:
                return "invalid email format"
        return None

    def post(self, payload: dict[str, Any]) -> dict[str, Any]:
        if error := self.validate_payload(payload):
            return {"error": error}
        user_id = payload["id"]
        name = payload.get("name")
        email = payload.get("email")
        try:
            user = self.user_service.update_user(
                user_id,
                name=name,
                email=email,
            )
        except UserServiceError as err:
            return {"error": str(err)}
        if not user:
            return {"error": "unknown error"}
        return {"user": asdict(user)}


def main():
    print()
    print("CREATE USERS")
    payload = {"name": "Anton", "email": "demkin@avito.ru"}
    resp = CreateUserHandler().post(payload)
    print(resp)
    print()
    payload = {"name": "Oleg", "email": "oleg@avito.ru"}
    resp = CreateUserHandler().post(payload)
    print(resp)
    payload = {"name": "Ivan", "email": "ivan@avito.ru"}
    resp = CreateUserHandler().post(payload)
    print(resp)

    print()
    print("GET USERS")
    payload = {"id": 0}
    resp = GetUserHandler().post(payload)
    print(resp)
    payload = {"id": 0}
    resp = GetUserHandler().post(payload)
    print(resp)
    payload = {"id": 2}
    resp = GetUserHandler().post(payload)
    print(resp)
    payload = {"id": 1}
    resp = GetUserHandler().post(payload)
    print(resp)

    print()
    print("HANDLE ERRORS")
    payload = {"id": -1}
    resp = GetUserHandler().post(payload)
    print(resp)
    payload = {"id": 42}
    resp = GetUserHandler().post(payload)
    print(resp)
    payload = {"name": "Anton", "email": "demkin@avito.ru"}
    resp = CreateUserHandler().post(payload)
    print(resp)
    payload = {"name": "Anton"}
    resp = CreateUserHandler().post(payload)
    print(resp)
    payload = {"name": "Anton", "email": "123"}
    resp = CreateUserHandler().post(payload)
    print(resp)
    payload = {"name": 123}
    resp = CreateUserHandler().post(payload)
    print(resp)
    payload = {"name": "A", "email": "demkin@avito.ru"}
    resp = CreateUserHandler().post(payload)
    print(resp)

    print()
    print("UPDATE USER")
    payload = {"id": 0, "email": "antondemkin@yandex.ru"}
    resp = UpdateUserHandler().post(payload)
    print(resp)

    print()
    print("UPDATE USER ERROR")
    payload = {"id": 42, "email": "antondemkin@yandex.ru"}
    resp = UpdateUserHandler().post(payload)
    print(resp)

    print()
    print("GET UPDATED USER")
    payload = {"id": 0}
    resp = GetUserHandler().post(payload)
    print(resp)
    payload = {"id": 0}
    resp = GetUserHandler().post(payload)
    print(resp)

    print()
    print("ALL OK")


if __name__ == "__main__":
    main()
