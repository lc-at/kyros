import pickle


class Session:
    client_id = None
    server_id = None

    client_token = None
    server_token = None
    client_secret = None

    secret = None
    shared_secret = None
    shared_secret_expanded = None

    private_key = None
    public_key = None

    keys_encrypted = None
    keys_decrypted = None

    enc_key = None
    mac_key = None

    wid = None

    @staticmethod
    def from_file(filename):
        with open(filename, "rb") as file:
            return pickle.load(file)

    def save_to_file(self, filename):
        with open(filename, "wb") as file:
            return pickle.dump(self, file)
