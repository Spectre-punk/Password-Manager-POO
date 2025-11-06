package src.passwordManager.exceptions;

public class DuplicateEntryException extends PasswordManagerException{
    public DuplicateEntryException(String msg){
        super(msg);
    }
}
