#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 15 09:04:07 2022

@author: ga
"""
import secrets
import socket
import AlgoGSM
import time


def startServer():

    host = "localhost"
    port = 5000
    addr = (host,port)
    ki = "6bd96f7fdb64e0a02515efb0c0982d34"

    server_socket = socket.socket()  # get instance
    server_socket.bind((host, port))  # bind host address and port together
    server_socket.listen(1) # listen 1 client 
    conn, address = server_socket.accept()  # accept new connection
    
    print("Connection from: " + str(address))
    serverGSM=ServerGSM(conn,ki);
    if serverGSM.authClient():
        serverGSM.sartCom()
        conn.close()  # close the connection
    else:
        conn.close()  # close the connection


class ServerGSM(): 
    def __init__(self,conn,ki):
        self.state=0;
        self.buf = 1024
        self.fileToSend = "serverSend.txt"
        self.isfileToSend = True
        self.conn = conn
        self.ki=ki
        
    # Authentification    
    def authClient(self):
        
        #1. generate SRES
        RAND = secrets.token_hex(16)
        #print(SRES,len(SRES))
        #2. Send to client
        self.conn.send(RAND.encode())
        #3. calculate challenge
        SRES_byte=AlgoGSM.A3(bytes.fromhex(RAND), bytes.fromhex(self.ki))
        #print("challenge", SRES_byte,len(SRES_byte))
        
        #4. control client
        dataRcv = self.conn.recv(self.buf);
        #print(dataRcv)
        if dataRcv != SRES_byte:
            print("Challenge failed, disconnection")
            result="fail"
            self.conn.send(result.encode())
            self.conn.close()  # close the connection
            return 0
        print("Authentification suceeded")
        result="pass"
        self.conn.send(result.encode())
        
        #5. deriv Key
        self.kc_byte=AlgoGSM.A8(bytes.fromhex(RAND), bytes.fromhex(self.ki))
        self.kc_startTime = time.time();
        
        #print("Kc =",self.kc_byte)
        
        
        return 1
    
    def sartCom(self):
        
        while True:
            #1. recieve IV from client
            nonce = self.conn.recv(self.buf).decode()
            #print("IV: ", nonce)  
            #print("kc:",self.kc_byte)
            if not nonce:
                # if data is not received break
                break
            #2 recieve data and decrypt
            cypher_byte = self.conn.recv(self.buf)
            print("cypher from client: ", cypher_byte) 
            data= AlgoGSM.A5_dec(cypher_byte, self.kc_byte, bytes.fromhex(nonce))
            print("Client says: ", data) 
            
            ##################################################################
            # Atfer 20min necessary to regenerate kc, restart authentification
            if (time.time()-self.kc_startTime) >= (20*60):
                message = "regKi"
                reAuth=True;
            else:
                reAuth=False;
                # send file in the first step
                if self.isfileToSend:
                    with open (self.fileToSend, "r") as myfile:
                        message=myfile.read().replace('\n', '')
                    self.isfileToSend=False
                else:
                    # message to client
                    message = input(" -> ")  # take input
                    

            #1. send IV from client
            nonce = secrets.token_hex(4)
            self.conn.send(nonce.encode())

            #2. encrypt and send data 
            cypher_byte = AlgoGSM.A5_enc(message, self.kc_byte, bytes.fromhex(nonce))
            self.conn.send(cypher_byte)  # send message     
            
            #3. if necessary restart authentification
            if reAuth:
                print("Restart authentification process")
                self.authClient()
            



        
