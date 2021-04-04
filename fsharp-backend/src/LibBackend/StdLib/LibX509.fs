module LibBackend.StdLib.LibX509

open System
open System.Threading.Tasks
open System.Numerics
open System.Text
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open FSharp.Control.Tasks
open FSharpPlus

open LibExecution.RuntimeTypes
open Prelude

module Errors = LibExecution.Errors

let fn = FQFnName.stdlibFnName

let err (str : string) = Value(Dval.errStr str)

let incorrectArgs = LibExecution.Errors.incorrectArgs

let varA = TVariable "a"
let varB = TVariable "b"

let fns : List<BuiltInFn> =
  [ { name = fn "X509" "pemCertificatePublicKey" 0
 
    ; parameters = [Param.make "pemCert" TStr ""]
    ; returnType = TResult(TStr, TStr)
    ; description =
        "Extract the public key from a PEM encoded certificate and return the key in PEM format."
    ; fn =
          (function
          | _, [DStr cert] ->
            ( try
                
                let mutable span = new ReadOnlySpan<char>(cert.ToCharArray())
                let fields = PemEncoding.Find span
                let label = fields.Base64Data
                let range = span.Slice(label.Start.Value, label.End.Value).ToString()
                let pem = new X509Certificate2(Convert.FromBase64String(range))
                let mutable pubLabel = "PUBLIC_KEY".AsSpan()
                let pemData = new ReadOnlySpan<byte>(pem.PublicKey.EncodedKeyValue.RawData)
                let pubPem = PemEncoding.Write(pubLabel, pemData)
                pubPem
                |> String
                |> DStr
                |> Ok
                |> DResult
                |> Value
              with e -> Value(DResult(Error(DStr e.Message))))
          | _ -> incorrectArgs ())
    ; sqlSpec = NotYetImplementedTODO
    ; previewable = Impure
    ; deprecated = NotDeprecated } ]
 