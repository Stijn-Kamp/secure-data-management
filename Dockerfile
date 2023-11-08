FROM ubuntu:23.04
RUN apt update
RUN apt install -y libgmp-dev git build-essential flex bison libtool autoconf-archive python-is-python3 python3-venv python3-pip
RUN git clone https://github.com/blynn/pbc.git /tmp/pbc
WORKDIR /tmp/pbc
RUN sh setup
RUN ./configure --prefix=/usr --enable-shared
RUN make
RUN make install
RUN ldconfig
RUN git clone https://github.com/Stijn-Kamp/secure-data-management.git /mpeck
WORKDIR /mpeck
RUN python -m venv venv
RUN git clone https://github.com/20Thomas02/pypbc.git /tmp/pypbc
RUN bash -c 'source venv/bin/activate && cd /tmp/pypbc && pip install . && pip install -r requirements.txt'
