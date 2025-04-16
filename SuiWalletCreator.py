import hashlib
import hmac
import struct
from ecdsa import SigningKey, Ed25519
from hashlib import blake2b
from mnemonic import Mnemonic
from bech32 import bech32_encode, convertbits
import asyncio



a = """

     █░█ ▄▀█ █▄░█ █▀▄ █▀▀ █░█
     █▀█ █▀█ █░▀█ █▄▀ ██▄ ▀▄▀


"""



print(a)




BIP39_PBKDF2_ROUNDS = 2048
BIP39_SALT_MODIFIER = "mnemonic"
BIP32_PRIVDEV = 0x80000000
DERIVATION_PATH = "m/44'/0'/0'/0/0"
BIP32_SEED_ED25519 = b"ed25519 seed"


class SimpleWalletGenerator:
    def __init__(self, wallet_count, filename, words=None):
        self.wallet_count = wallet_count
        self.filename = filename
        self.words = words
        self.wallets = []

    def generate_mnemonic(self):
        mnemonic_generator = Mnemonic("english")
        return mnemonic_generator.generate(strength=256)

    @staticmethod
    def mnemonic_to_bip39seed(mnemonic, passphrase=""):
        salt = bytes(BIP39_SALT_MODIFIER + passphrase, 'utf8')
        return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf8'), salt, BIP39_PBKDF2_ROUNDS)

    def mnemonic_to_private_key(self, mnemonic, passphrase=""):
        bip39seed = self.mnemonic_to_bip39seed(mnemonic, passphrase)
        key = hmac.new(BIP32_SEED_ED25519, bip39seed, hashlib.sha512).digest()
        private_key = key[:32]  # Take first 32 bytes
        return private_key

    @staticmethod
    def private_key_to_bech32(private_key_hex, hrp="suiprivkey"):
        private_key_bytes = bytes.fromhex(private_key_hex)
        key_with_type = b'\x00' + private_key_bytes
        bech32_data = convertbits(key_with_type, 8, 5)
        return bech32_encode(hrp, bech32_data)

    def generate_wallet(self, mnemonic):
        private_key = self.mnemonic_to_private_key(mnemonic)
        public_key = self.private_key_to_public_key(private_key)
        sui_address = self.generate_sui_address(public_key)
        private_key_hex = private_key.hex()
        sui_private_key_bech32 = self.private_key_to_bech32(private_key_hex)
        return sui_address, sui_private_key_bech32

    def private_key_to_public_key(self, private_key):
        sk = SigningKey.from_string(private_key, curve=Ed25519)
        vk = sk.verifying_key
        return vk.to_string()

    @staticmethod
    def generate_sui_address(public_key_bytes) -> str:
        serializer = bytearray([0x00]) + public_key_bytes
        hashed = blake2b(bytes(serializer), digest_size=32)
        return "0x" + hashed.hexdigest()

    async def generate_wallets(self):
        tasks = []
        for _ in range(self.wallet_count):
            mnemonic = self.generate_mnemonic()  # Her cüzdan için yeni bir mnemonic oluşturuyoruz
            tasks.append(self.generate_wallet_async(mnemonic))

        wallets = await asyncio.gather(*tasks)

        # Cüzdanları bir txt dosyasına yazıyoruz
        with open(f"{self.filename}.txt", "a") as file:
            for wallet in wallets:
                file.write(f"Address: {wallet[0]}\nPrivate Key: {wallet[1]}\n\n")

    async def generate_wallet_async(self, mnemonic):
        # Bu fonksiyon her seferinde yeni bir cüzdan oluşturacak
        return self.generate_wallet(mnemonic)

    async def run(self):
        await self.generate_wallets()


if __name__ == "__main__":
    wallet_count = int(input("Kaç tane cüzdan oluşturmak istersiniz? "))
    filename = input("Dosya adı girin (örneğin 'wallets'): ")
    wallet_generator = SimpleWalletGenerator(wallet_count, filename)
    asyncio.run(wallet_generator.run())
