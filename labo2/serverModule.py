#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 15 09:04:07 2022

@author: ga
"""
import secrets
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from base64 import b64encode
import socket

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
        blowfishChallenge= Blowfish.new(bytes.fromhex(self.ki), AES.MODE_ECB) # only one bloc
        RAND_comp_byte=bytes.fromhex(RAND)[0:8] # compresse RAND to 8 bytes, to work with one bloc
        SRES_byte=blowfishChallenge.encrypt(RAND_comp_byte);
        #print("challenge", chalcypher_byte,len(chalcypher_byte))
        
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
        aesKc= AES.new(bytes.fromhex(self.ki), AES.MODE_ECB) # only one bloc
        self.kc_byte=aesKc.encrypt(aesKc.encrypt(bytes.fromhex(RAND))); # todo: Use a different algo
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
            #2. init aes
            aesCom = AES.new(self.kc_byte, AES.MODE_CTR, nonce=bytes.fromhex(nonce)) 
            
            #3. recieve data and decrypt
            cypher_byte = self.conn.recv(self.buf)
            
            data=aesCom.decrypt(cypher_byte);
            print("from connected user: ", data.decode() ) 
            
            # message to client
            message = input(" -> ")  # take input

            #1. send IV from client
            nonce = secrets.token_hex(8)
            self.conn.send(nonce.encode())

            #2. init aes
            aesCom = AES.new(self.kc_byte, AES.MODE_CTR, nonce=bytes.fromhex(nonce)) 
            
            #3. encrypt and send data 
            cypher_byte = aesCom.encrypt(bytes(message,'utf-8'))
            self.conn.send(cypher_byte)  # send message           



        
