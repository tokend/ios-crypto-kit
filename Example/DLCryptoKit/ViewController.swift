import UIKit
import DLCryptoKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.runSign()
    }
    
    func runSign() {
        for _ in 0..<100 {
            guard let key = try? ECDSA.KeyData() else {
                print("failed init")
                continue
            }
            
            let data = Common.Random.generateRandom(length: 100)
            guard let signature = try? ECDSA.signED25519(data: data, keyData: key) else {
                print("failed to sign")
                continue
            }
            
            print("signed data: \(signature.hexadecimal())")
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(3), execute: {
            self.runSign()
        })
    }
}
