FROM ubuntu:18.04

RUN apt-get update && apt-get install -y build-essential socat && rm -rf /var/lib/apt/lists/*

COPY chall /home/ctf_player/chall
COPY flag flag
WORKDIR /home/ctf_player/chall

RUN make && rm -f Makefile main.c

RUN useradd -d /home/ctf_player ctf_player
RUN chown -R ctf_player:ctf_player /home/ctf_player

USER ctf_player

EXPOSE 5159

CMD ["socat", "-t", "10", "-T", "60", "-v", "TCP-LISTEN:5159,reuseaddr,fork", "EXEC:/home/ctf_player/chall/painter"]