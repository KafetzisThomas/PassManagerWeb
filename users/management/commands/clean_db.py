from django.core.management.base import BaseCommand
from django.db import connection
from ...models import CustomUser


class Command(BaseCommand):
    help = "Cleans up db table by removing rows with NULL values in specified column (last_login)."

    def handle(self, *args, **kwargs):
        db_table = CustomUser._meta.db_table
        db_column = "last_login"

        with connection.cursor() as cursor:
            cursor.execute(f"DELETE FROM {db_table} WHERE {db_column} IS NULL")
            deleted_rows = cursor.rowcount

        self.stdout.write(
            self.style.SUCCESS(
                f"Deleted {deleted_rows} rows from {db_table} where {db_column} was NULL."
            )
        )
