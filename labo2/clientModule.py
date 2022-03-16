#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 15 09:04:07 2022

@author: ga
"""
import secrets
import socket
import AlgoGSM

def startCient():

    host = "localhost"
    port = 5000
    addr = (host,port)
    ki = "6bd96f7fdb64e0a02515efb0c0982d34"

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    
    clientGSM=ClientGSM(client_socket,ki);
    if clientGSM.auth():
        clientGSM.sartCom()
        client_socket.close()  # close the connection
    else:
        client_socket.close()  # close the connection
    


class ClientGSM(): 
    def __init__(self,conn,ki):
        self.state=0;
        self.buf = 1024
        self.fileToSend = "clientSend.txt"
        self.isfileToSend = True
        self.conn = conn
        self.ki=ki
        
    # Authentification    
    def auth(self):
        
        #1. wait for challenge
        RAND = self.conn.recv(1024).decode()  # receive response
        
        #2. solve challenge and send
        SRES_byte=AlgoGSM.A3(bytes.fromhex(RAND), bytes.fromhex(self.ki))
        self.conn.send(SRES_byte)
        
        # wait anser from server
        answer = self.conn.recv(1024).decode()  # receive response
        if answer != 'pass':
            print("Authentification failed, disconnection")
            return 0;
        
        #5. deriv Key
        self.kc_byte=AlgoGSM.A8(bytes.fromhex(RAND), bytes.fromhex(self.ki))
        #print("Kc =",len(self.kc_byte))
        
        return 1
    
    def sartCom(self):
        
        while True:
            # send file in the first step
            if self.isfileToSend:
                with open (self.fileToSend, "r") as myfile:
                    message=myfile.read().replace('\n', '')
                self.isfileToSend=False    
                #print(message)
            else:
                message = input(" -> ")  # take input
            # todo:
            #with open('data.txt', 'r') as f:
            #    data = f.read()

            if message == "exit":
                break;
            
            #1. send IV from client
            nonce = secrets.token_hex(4)
            self.conn.send(nonce.encode())
            #print("IV:",nonce)
            #print("kc:",self.kc_byte)
  
            #2. encrypt and send data 
            cypher_byte = AlgoGSM.A5_enc(message, self.kc_byte, bytes.fromhex(nonce))
            self.conn.send(cypher_byte)  # send message
            
            ###################################################################
            # wait for message from server
            nonce = self.conn.recv(self.buf).decode()
            if not nonce:
                # if data is not received break
                break
            
            #2 recieve data and decrypt
            cypher_byte = self.conn.recv(self.buf)
            print("cypher from server: ", cypher_byte) 
            data= AlgoGSM.A5_dec(cypher_byte, self.kc_byte, bytes.fromhex(nonce))
            if data == "regKi":
                print("Restart Authentification")
                self.auth()
            else:
                print("server says: ", data ) 
            



        
