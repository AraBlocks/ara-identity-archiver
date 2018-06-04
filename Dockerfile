FROM arablocks/ann
WORKDIR /opt/ann/identity-archiver
ADD . /opt/ann/identity-archiver
ENTRYPOINT [ "ann",  "-t", "." ]
