def close(self, active=0):
    """
    Finish the connection and release resources. For simplicity, assume that
    after a socket is closed, neither futher sends nor receives are allowed.
    """
    #############################################################################
    # TODO: YOUR CODE HERE                                                      #
    #############################################################################
    if active == 0:
        pass
    elif active == 1 and self.status != Status.Passive_fin2:
        self.status = Status.Passive_fin1
    finpkt: Segment
    while self.status != Status.Closed:
        if self.status == Status.Active:
            self.status = Status.Active_fin1
        elif self.status == Status.Passive_fin1:
            self.status = Status.Passive_fin2
        finpkt = Segment(fin=1, seq=self.status.value.value, seq_ack=self.seqack)
        # check and process send queue
        if finpkt.fin == 1:
            self.sendto(data=finpkt, addr=self._send_to)

    #############################################################################
    #                             END OF YOUR CODE                              #
    #############################################################################


def _close(self):
    while not self.seq_que.empty():
        time.sleep(1)
    self.status = Status.Closed
    print("Closed socket to: ", self._send_to)
    super().close()


def close_threading(self):
    while True:
        while self.status != Status.Closed or not self.seq_que.empty():
            time.sleep(0.0001)

        if self.status == Status.Closed:
            break

        if self.status == Status.Active_fin1:
            self.status = Status.Active_fin2
        elif self.status == Status.Passive_fin2:
            self.status = Status.Closed
            self._close()
        elif self.status == Status.Active_fin2:
            self.status = Status.Closed
            self._close()


def _send(self, send_to):
    self._send_to = send_to
