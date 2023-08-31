import jwt
import json
import argparse 


parser = argparse.ArgumentParser(add_help=True, description="Decode some Azure JWTs for graph token")
parser.add_argument("-f", "--file", action="store", help="Path to text file containing new line separated JWTs.", required=True)

args = parser.parse_args()

path = args.file

with open(f"{path}", "r") as f:
    tokens = f.read().splitlines()

for token in tokens:
    try:
        decoded_header = jwt.get_unverified_header(token)
        algo = decoded_header.get("alg", "")
        decoded_data  = jwt.decode(jwt=token, algorithms=[f"{algo}"], options={"verify_signature": False})

        aud = decoded_data.get("aud", "")

        if aud == "https://graph.microsoft.com/":
            print(token)
            print("")
            print(json.dumps(decoded_data, indent=4))
            exit()
    
    except jwt.exceptions.DecodeError:
        continue
