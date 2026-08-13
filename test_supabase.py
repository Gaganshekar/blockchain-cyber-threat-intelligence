import os
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")

print("Supabase URL found:", bool(url))
print("Supabase key found:", bool(key))

if not url or not key:
    print("ERROR: Supabase credentials were not found in .env")
    exit()

try:
    supabase = create_client(url, key)

    response = supabase.table("threats").select("*").limit(1).execute()

    print("SUCCESS: Connected to Supabase!")
    print("Threat table response:", response.data)

except Exception as error:
    print("SUPABASE CONNECTION ERROR:")
    print(error)