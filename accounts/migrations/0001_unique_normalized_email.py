from django.db import migrations


INDEX_NAME = "auth_user_email_normalized_uniq"
# These are the whitespace characters removed by Python's str.strip().
TRIM_CHARACTERS = (
    r"U&'\0009\000A\000B\000C\000D\001C\001D\001E\001F\0020\0085\00A0\1680"
    r"\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000'"
)
NORMALIZED_EMAIL = (
    f'LOWER(BTRIM(email, {TRIM_CHARACTERS}) COLLATE pg_catalog."und-x-icu")'
)


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.RunSQL(
            sql=[
                "LOCK TABLE auth_user IN SHARE ROW EXCLUSIVE MODE",
                f"""
                DO $$
                DECLARE
                    collision_groups bigint;
                BEGIN
                    SELECT COUNT(*) INTO collision_groups
                    FROM (
                        SELECT {NORMALIZED_EMAIL}
                        FROM auth_user
                        WHERE {NORMALIZED_EMAIL} <> ''
                        GROUP BY {NORMALIZED_EMAIL}
                        HAVING COUNT(*) > 1
                    ) AS collisions;

                    IF collision_groups > 0 THEN
                        RAISE EXCEPTION
                            'Grupos de correos normalizados en colisión: %', collision_groups;
                    END IF;
                END;
                $$;
                """,
                f"""
                CREATE UNIQUE INDEX {INDEX_NAME}
                ON auth_user (({NORMALIZED_EMAIL}))
                WHERE {NORMALIZED_EMAIL} <> ''
                """,
            ],
            reverse_sql=f"DROP INDEX {INDEX_NAME}",
        ),
    ]
