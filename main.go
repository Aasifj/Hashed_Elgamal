//------------ Elgamal Using Eliptic Curves with Additional Authentication Data--------


package main

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"math/big"
	"os"
  "bufio"
  //"json"
 
  
//  "io/ioutil"
  "log"
  
  

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

//Here we define Public Parameters ( Curve Generator , Receiver's Public Key)
var G curves.Point                  
var key_pub curves.Point 
//var C1 curves.Point 
//var C2 curves.Point 


//type Key struct{
 // value curves.Point 
//}


func setup() *curves.Curve{
 	curve := curves.ED25519()  // Choosen curve : ED25519
  path :=".Generator.json"
  file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0777)

  G =curve.Point.Generator() 

  if(err!=nil){
    log.Fatalf("Error Creating File: %s",err)
    
  }
  
  
  _,err2:=fmt.Fprintln(file,G)
  if(err2!=nil){
    log.Fatalf("Error Writing\n")
  }
  fmt.Printf("\n___ SETUP PHASE COMPLETED ___\n\n")

  return curve 
  
}


func keygen(curve *curves.Curve) (curves.Scalar,curves.Point) { //Generates <Key_pri,key_pub> Pair
  pri :=curve.Scalar.Random(crand.Reader) 
  pub :=G.Mul(pri)
  path :=".Public_Parameters.json"
  file, err := os.OpenFile(path, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0777)

  if(err!=nil){
    log.Fatalf("Error Creating File: %s",err)
    
  }
  _,err2:=fmt.Fprintf(file,"Public Key(Hex):\n%x\n",pub.ToAffineCompressed())
  _,err2=fmt.Fprintf(file,"Public Key(Hex):\n%x\n",pri.Bytes())
  if(err2!=nil){
    log.Fatalf("Error Writing\n")
  }
  fmt.Printf("\n___ KeyGen Completed ___\n\n")

  return pri,pub  
}


func encryption(curve *curves.Curve, msg string,key_priv curves.Scalar) ([] byte,[12] byte,curves.Point ,curves.Point){

  //Inputs to function-> Curve used , Message to encrypt , Private key 


  
  C1 :=curve.Point.Generator().Mul(key_priv)
  M :=curve.Point.Hash([]byte(msg))
  C2 :=key_pub.Mul(key_priv).Add(M)

  
  path :=".Public_Parameters.json"
  file, _ := os.OpenFile(path, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0777)

  _,err2:=fmt.Fprintf(file,"C1(Hex):\n%x\n",C1.ToAffineCompressed())
  _,err2=fmt.Fprintf(file,"C2(Hex):\n%x\n",C2.ToAffineCompressed())
  if(err2!=nil){
    log.Fatalf("Error Writing\n")
  }

  symm_key :=key_pub.Mul(key_priv)             //Symmetric Key used by both parties    

  aeadKey, _ := core.FiatShamir(new(big.Int).SetBytes(symm_key.ToAffineCompressed()))
	block, _ := aes.NewCipher([]byte(aeadKey))
  
  aesGcm, _ := cipher.NewGCM(block)
 

  // Generates Additional Authentication Data 
  
	aad := C1.ToAffineUncompressed()
	aad = append(aad, C2.ToAffineUncompressed()...)
	var nonce [12]byte
	_, _ = crand.Read(nonce[:])                        // Random Nonce 
	aead := aesGcm.Seal(nil, nonce[:], []byte(msg), aad)

  return aead,nonce,C1,C2 
  
  
}

func decryption(C1 curves.Point, C2 curves.Point,aead []byte,nonce [12]byte,key_pri curves.Scalar) []byte{

  
  symm_key:=C1.Mul(key_pri)

  aeadKey, _ := core.FiatShamir(new(big.Int).SetBytes(symm_key.ToAffineCompressed()))
	block, _ := aes.NewCipher([]byte(aeadKey))
	aesGcm, _ := cipher.NewGCM(block)

	aad1 := C1.ToAffineUncompressed()
	aad1 = append(aad1, C2.ToAffineUncompressed()...)
	msg, _ := aesGcm.Open(nil, nonce[:], aead, aad1)
 
	fmt.Printf("\nReciever's private key:\t%x\n", key_pri.Bytes())
	fmt.Printf("Recievers's public key:\t%x\n", key_pub.ToAffineCompressed())
	fmt.Printf("\nC1:\t%x\n", C1.ToAffineCompressed())
	fmt.Printf("C2:\t%x\n", C2.ToAffineCompressed())
	fmt.Printf("AAD:\t%x\n", aad1)
	fmt.Printf("Nonce:\t\t%x\n", nonce)
	fmt.Printf("Encrypted:\t%x\n", aead)
  fmt.Printf("\n === Receiver receives AEAD, Nonce, C1 and C2 and recovers message ===\n")


    path :=".Intermediate_Values.json"
  file, _ := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)

  _,err2:=fmt.Fprintf(file,"Nonce:\n%x\n",nonce)
  _,err2=fmt.Fprintf(file,"Encrypted Msg:\n%x\n",aead)
  if(err2!=nil){
    log.Fatalf("Error Writing\n")
  }

  
  return msg 

  
}

// func temp ()


func main() {

  // temp(msg,
  fmt.Printf("Enter Message To Encrypt: ")
	in := bufio.NewReader(os.Stdin)

  mymsg, _ := in.ReadString('\n')
  if(len(mymsg)==0){
    fmt.Printf("No Input Message\n")
    return 
  }
  fmt.Printf("\nOriginal Message: %s\n",mymsg)
	argCount := len(os.Args[1:])

	if argCount > 0 {
		mymsg = os.Args[1]       //alternate message as CLA 
	}                            
                               
	curve := setup()  // Choosen curve : ED25519 

  //--------------------------------- BY RECEIVER-----------
  x,temp := keygen(curve) // x -> Recievers Private Key 
  key_pub=temp             // key_pub -> Recievers Public Key

  //--------

  y:=curve.Scalar.Random(crand.Reader)     // Senders private Key used to Encrypt 
  
  aead,nonce,C1,C2:=encryption(curve,mymsg,y)

  recovered_msg:=decryption(C1,C2,aead,nonce,x)

  fmt.Printf("Recovered Msg: %s\n",recovered_msg)
  

}
