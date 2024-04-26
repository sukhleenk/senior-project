# your_app/management/commands/hash_password.py

from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from django.db import connection

class Command(BaseCommand):
    help = 'Generates a hashed password for a given plain text password and updates it for a user'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='The username of the user to update the password for')
        parser.add_argument('password', type=str, help='The plain text password to hash')

    def handle(self, *args, **kwargs):
        username = kwargs['username']
        password = kwargs['password']
        hashed_password = make_password(password)

        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE users
                SET Password = %s
                WHERE Username = %s
            """, [hashed_password, username])

        self.stdout.write(self.style.SUCCESS(f"Updated password for user '{username}'"))
