import sys
import os
import tempfile
import atheris

# 1. Enable bytecode instrumentation BEFORE importing Flask or app modules
atheris.instrument_imports()

# 2. Now import your app dependencies
from app import app, init_db
import app as app_module

def TestOneInput(data):
    """
    Fuzz target function called repeatedly by Atheris libFuzzer engine.
    """
    if len(data) < 4:
        return

    fdp = atheris.FuzzedDataProvider(data)
    
    # Set up an isolated temporary database in memory/temp folder for this fuzz run
    tmp_dir = tempfile.TemporaryDirectory()
    db_path = os.path.join(tmp_dir.name, "fuzz_test.sqlite3")
    
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False  # Disable CSRF token checks so fuzzer can hit internal endpoints directly
    app_module.DB_PATH = db_path
    
    try:
        with app.app_context():
            init_db()
            
        client = app.test_client()

        # Extract randomized inputs from raw byte stream
        fuzz_str1 = fdp.ConsumeUnicodeNoSurrogates(32)
        fuzz_str2 = fdp.ConsumeUnicodeNoSurrogates(32)
        fuzz_amount = fdp.ConsumeIntInRange(-1000, 5000)

        # Pick a target route randomly based on fuzzer data
        target_route = fdp.ConsumeIntInRange(1, 3)

        if target_route == 1:
            # Fuzz Registration endpoint
            client.post("/register", data={
                "full_name": fuzz_str1,
                "username": fuzz_str2,
                "email": f"{fuzz_str2}@example.test",
                "password": "Password123!",
                "confirm_password": "Password123!"
            })
        elif target_route == 2:
            # Fuzz Login endpoint
            client.post("/login", data={
                "username": fuzz_str1,
                "password": fuzz_str2
            })
        elif target_route == 3:
            # Fuzz Transfer endpoint
            client.post("/transfer", data={
                "recipient_account": fuzz_str1,
                "amount": str(fuzz_amount)
            })

    except (ValueError, KeyError, TypeError):
        # Catch anticipated application validation rejections
        pass
    finally:
        tmp_dir.cleanup()

# 3. Initialize and Start Fuzzer
atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()