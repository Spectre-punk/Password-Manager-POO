package src.passwordManager.exceptions;

public class InvalidMasterPasswordException extends PasswordManagerException{
    public InvalidMasterPasswordException(String mns){
        super(mns);
    }
}
