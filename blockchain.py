import hashlib
import json

from datetime import datetime, timezone
from dataclasses import dataclass, asdict


@dataclass
class Block:

    index: int
    timestamp: str
    data: dict
    previous_hash: str
    nonce: int
    hash: str


class Blockchain:

    def __init__(self, difficulty=4):

        self.chain = []

        self.difficulty = difficulty

        self.create_genesis_block()


    # ==================================================
    # CREATE GENESIS BLOCK
    # ==================================================

    def create_genesis_block(self):

        genesis = Block(

            index=0,

            timestamp=datetime.now(
                timezone.utc
            ).isoformat(),

            data={
                "message": "Genesis Block"
            },

            previous_hash="0",

            nonce=0,

            hash=""
        )

        genesis.hash = self.calculate_hash(
            genesis
        )

        self.chain.append(
            genesis
        )


    # ==================================================
    # GET LATEST BLOCK
    # ==================================================

    def get_latest_block(self):

        return self.chain[-1]


    # ==================================================
    # CALCULATE HASH
    # ==================================================

    def calculate_hash(self, block):

        block_string = json.dumps(
            {
                "index": block.index,

                "timestamp": block.timestamp,

                "data": block.data,

                "previous_hash":
                    block.previous_hash,

                "nonce": block.nonce
            },

            sort_keys=True
        ).encode()

        return hashlib.sha256(
            block_string
        ).hexdigest()


    # ==================================================
    # PROOF OF WORK
    # ==================================================

    def proof_of_work(self, block):

        block.nonce = 0

        computed_hash = self.calculate_hash(
            block
        )

        while not computed_hash.startswith(
            "0" * self.difficulty
        ):

            block.nonce += 1

            computed_hash = self.calculate_hash(
                block
            )

        return computed_hash


    # ==================================================
    # ADD NEW BLOCK
    # ==================================================

    def add_block(
        self,
        threat_data,
        timestamp=None
    ):

        previous = self.get_latest_block()


        # --------------------------------------------------
        # Use database timestamp when rebuilding.
        # Otherwise create a new UTC timestamp.
        # --------------------------------------------------

        if timestamp is None:

            timestamp = datetime.now(
                timezone.utc
            ).isoformat()

        else:

            timestamp = str(
                timestamp
            )


        block = Block(

            index=previous.index + 1,

            timestamp=timestamp,

            data=threat_data,

            previous_hash=previous.hash,

            nonce=0,

            hash=""
        )


        # --------------------------------------------------
        # Mine block
        # --------------------------------------------------

        block.hash = self.proof_of_work(
            block
        )


        # --------------------------------------------------
        # Add block to blockchain
        # --------------------------------------------------

        self.chain.append(
            block
        )


        return block


    # ==================================================
    # VERIFY BLOCKCHAIN
    # ==================================================

    def is_chain_valid(self):

        # Verify genesis block hash too
        genesis = self.chain[0]

        if genesis.hash != self.calculate_hash(
            genesis
        ):

            return False


        for i in range(
            1,
            len(self.chain)
        ):

            current = self.chain[i]

            previous = self.chain[i - 1]


            # --------------------------------------------------
            # Verify current hash
            # --------------------------------------------------

            if current.hash != self.calculate_hash(
                current
            ):

                return False


            # --------------------------------------------------
            # Verify previous hash
            # --------------------------------------------------

            if current.previous_hash != previous.hash:

                return False


            # --------------------------------------------------
            # Verify Proof of Work
            # --------------------------------------------------

            if not current.hash.startswith(
                "0" * self.difficulty
            ):

                return False


        return True


    # ==================================================
    # DISPLAY CHAIN
    # ==================================================

    def display_chain(self):

        chain = []

        for block in self.chain:

            chain.append(
                asdict(block)
            )

        return chain


    # ==================================================
    # GET CHAIN
    # ==================================================

    def get_chain(self):

        return self.display_chain()


    # ==================================================
    # TOTAL BLOCKS
    # ==================================================

    def total_blocks(self):

        return len(
            self.chain
        )


    # ==================================================
    # BLOCKCHAIN STATISTICS
    # ==================================================

    def get_statistics(self):

        return {

            "total_blocks":
                len(self.chain),

            "difficulty":
                self.difficulty,

            "valid":
                self.is_chain_valid()
        }


    # ==================================================
    # GET LATEST HASH
    # ==================================================

    def get_latest_hash(self):

        return self.get_latest_block().hash


    # ==================================================
    # EXPORT BLOCKCHAIN
    # ==================================================

    def export_json(self):

        return json.dumps(

            self.display_chain(),

            indent=4
        )


    # ==================================================
    # VERIFY SINGLE BLOCK
    # ==================================================

    def verify_block(self, index):

        if index < 0 or index >= len(
            self.chain
        ):

            return False


        block = self.chain[index]

        calculated = self.calculate_hash(
            block
        )


        if calculated != block.hash:

            return False


        # Genesis block
        if index == 0:

            return (
                block.previous_hash == "0"
            )


        # Verify link to previous block
        previous = self.chain[
            index - 1
        ]

        if block.previous_hash != previous.hash:

            return False


        # Verify PoW
        if not block.hash.startswith(
            "0" * self.difficulty
        ):

            return False


        return True


    # ==================================================
    # BLOCKCHAIN INFORMATION
    # ==================================================

    def blockchain_info(self):

        return {

            "Blocks":
                len(self.chain),

            "Difficulty":
                self.difficulty,

            "Valid":
                self.is_chain_valid(),

            "Latest Hash":
                self.get_latest_hash()
        }