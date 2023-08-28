
create table if not exists certificates (
    --Public key fingerprint of the user this certificate is for
    userid integer primary key not null,
    --UNIX timestamp of when this certificate was created
    creation_timestamp integer not null,
    --Time-to-live for the certificate
    ttl integer not null,
    --Encoded data + signature of the certificate
    data blob not null,
) strict
