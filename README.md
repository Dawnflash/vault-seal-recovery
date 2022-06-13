# vault-seal-recovery

This is a simple tool for recovering an auto-sealed Vault from a disaster scenario where the KMS key is removed.

The tool only supports:
- Raft storage backend
- AWS KMS

## Principle

To recover from the loss of the auto-seal key (in this case the KMS key) the two objects it seals must be re-encrypted and injected into the storage:
- the root encryption key (also known as the master key or the barrier key)
- the recovery key

The root key can be exfiltrated from memory of a still-running unsealed Vault instance. I use a slightly modified PoC of the original project [vault-exfiltrate](https://github.com/slingamn/vault-exfiltrate).

The recovery key (if lost) can be simply re-generated. The key is actually just an authentication token and doesn't in fact encrypt anything. The program lets you create a new one with no Shamir splitting. If you desire that, you can just do a proper Vault rekey post-recovery.

## Usage

The tool assumes you've already created a new KMS key. It consists of two steps, dump and inject.

### Sealed key dump

This step dumps the sealed keys as well as their plain versions to stdout. It requires an unsealed running Vault instance.

Since the Raft DB is locked by the running Vault process, the tool will attempt to make a working temp copy. This may fail on busy instances. Just rerun the dump step if this gives you trouble.

```
./vault-seal-recovery dump -k <KMS_KEY_ID> [-f <VAULT_RAFT_DB_PATH>] [-r] <VAULT_PID>
```

Pass `-r` to also generate a new recovery key. It will be dumped to stdout. The base64 output is factically the key you should use afterwards. `VAULT_PID` must be that of a running unsealed Vault instance.

### Sealed key injection

Then you'll need to stop Vault, configure it to use the new KMS key and run
```
./vault-seal-recovery inject [-r] [-f <VAULT_RAFT_DB_PATH>]
```

Passing `-r` will inject the dumped recovery key and config.

Then start Vault again.
