"""Database models for identities, encrypted assets, sharing, and audit events."""

from __future__ import annotations

from datetime import UTC, datetime

from flask_login import UserMixin
from sqlalchemy.ext.hybrid import hybrid_property

from .extensions import db


def utcnow() -> datetime:
    # Store UTC as a naive value for consistent SQLite/Postgres comparisons.
    return datetime.now(UTC).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "app_user"

    id = db.Column(db.Integer, primary_key=True)
    auth_subject = db.Column(db.Uuid(as_uuid=False), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    avatar_filename = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(20), nullable=False, default="user", index=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    session_version = db.Column(db.Integer, nullable=False, default=1)
    password_changed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    encrypted_files = db.relationship(
        "EncryptedFile", back_populates="user", cascade="all, delete-orphan", lazy=True
    )
    activity_logs = db.relationship("ActivityLog", back_populates="user", lazy=True)
    shared_files_sent = db.relationship(
        "SharedFile",
        foreign_keys="SharedFile.shared_by_user_id",
        back_populates="shared_by",
        cascade="all, delete-orphan",
        lazy=True,
    )
    shared_files_received = db.relationship(
        "SharedFile",
        foreign_keys="SharedFile.shared_with_user_id",
        back_populates="shared_with",
        cascade="all, delete-orphan",
        lazy=True,
    )

    @hybrid_property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @is_admin.setter
    def is_admin(self, value: bool) -> None:
        self.role = "admin" if value else "user"

    @is_admin.expression
    def is_admin(cls):  # type: ignore[no-untyped-def]
        return cls.role == "admin"


class EncryptedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("app_user.id"), nullable=False, index=True)
    storage_name = db.Column(db.String(128), unique=True, nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    algorithm = db.Column(db.String(20), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    is_text = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    user = db.relationship("User", back_populates="encrypted_files")
    shared_instances = db.relationship(
        "SharedFile", back_populates="encrypted_file", cascade="all, delete-orphan", lazy=True
    )

    @property
    def owner(self) -> User:
        return self.user


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("app_user.id", ondelete="SET NULL"), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)
    target_type = db.Column(db.String(50), nullable=True)
    target_id = db.Column(db.String(128), nullable=True)
    success = db.Column(db.Boolean, nullable=False, default=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    user = db.relationship("User", back_populates="activity_logs")


class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_file_id = db.Column(db.Integer, db.ForeignKey("encrypted_file.id"), nullable=False, index=True)
    shared_by_user_id = db.Column(db.Integer, db.ForeignKey("app_user.id"), nullable=False, index=True)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey("app_user.id"), nullable=False, index=True)
    permissions = db.Column(db.String(20), nullable=False, default="download")
    message = db.Column(db.Text, nullable=True)
    shared_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    encrypted_file = db.relationship("EncryptedFile", back_populates="shared_instances")
    shared_by = db.relationship("User", foreign_keys=[shared_by_user_id], back_populates="shared_files_sent")
    shared_with = db.relationship("User", foreign_keys=[shared_with_user_id], back_populates="shared_files_received")

    @property
    def owner(self) -> User:
        return self.shared_by

    @property
    def recipient(self) -> User:
        return self.shared_with

    @property
    def filename(self) -> str:
        return self.encrypted_file.original_filename

    @property
    def access_level(self) -> str:
        return self.permissions


class DownloadToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("app_user.id"), nullable=False, index=True)
    storage_area = db.Column(db.String(20), nullable=False)
    relative_name = db.Column(db.String(128), nullable=False)
    download_name = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
