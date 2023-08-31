package pinecone.springsecuritydemo.model.request;

import lombok.Data;

@Data
public class UserRegisterRequest {

    private String email;
    private String password;
}
