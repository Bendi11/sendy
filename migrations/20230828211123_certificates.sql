create table if not exists certificates (
    -- For internal links in database
    idx integer primary key,
    --Public key fingerprint of the user this certificate is for
    userid blob unique not null,
    --UNIX timestamp of when this certificate was created
    creation_timestamp text not null,
    --Time-to-live for the certificate
    ttl integer not null,
    --Encoded data + signature of the certificate
    data blob not null
) strict;

-- Channels that contain basic metadata for a category of messages
create table if not exists channels (
    -- For internal links in database
    idx integer primary key,
    --Hash of the channel seed
    channelid blob unique not null,
    -- Last update timestamp 
    last_update text not null,
    -- Certificate ID of the creator of the channel
    owneridx integer not null,
    -- Encoded data + signature of the channel record
    data blob not null,
    foreign key(owneridx) references certificates(idx)
) strict;

create table if not exists messages (
    -- Hash of the message text + channel id + author id
    msgid blob primary key not null,
    -- ID of the channel this message was sent in
    channelidx integer not null,
    -- The last time this message was updated
    last_update text not null,
    -- Public key fingerprint of the message author
    authoridx integer not null,
    -- Encoded text + signature of the message
    data blob not null,
    foreign key(channelidx) references channels(idx),
    foreign key(authoridx) references certificates(idx)
) strict;
