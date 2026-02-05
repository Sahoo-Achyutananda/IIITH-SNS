#### Step 6 : Implementing Fresh keys every round + strict synchronization 

- Even with:
    - AES encryption
    - HMAC integrity
    - FSM ordering
We still have a big weakness if you reuse keys.
    - Same key used again and again
    - Replay attacks become easier
    - If key is compromised → all messages exposed