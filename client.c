#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include <stdbool.h>

#include "helpers.h"
#include "requests.h"
#include "parson.h"

#define HOST "34.254.242.81"
#define PORT 8080

#define REGISTER_URL "/api/v1/tema/auth/register"
#define LOGIN_URL "/api/v1/tema/auth/login"
#define ACCESS_URL "/api/v1/tema/library/access"
#define BOOKS_URL "/api/v1/tema/library/books"
#define LOGOUT_URL "/api/v1/tema/auth/logout"

#define MAX_STRING_LEN 100

int main(int argc, char *argv[])
{   
    char *message;
    char *response;
    int sockfd;

    char *cookie = NULL;
    // char *session_cookie = NULL;
    char *token = NULL;

    char command[100];

    bool logged_in = 0;
    bool in_library = 0;

    while (1) {
        fgets(command, MAX_STRING_LEN, stdin);
        command[strlen(command) - 1] = '\0';
        // posibilele actiuni pe care le pot realiza in library
        if (strcmp(command, "exit") == 0) {
            break;
        } else if (strcmp(command, "register") == 0) {
            if (logged_in) {
                printf("User already logged in. In order to register please log out first.\n");
            } else {
                char username[MAX_STRING_LEN], password[MAX_STRING_LEN];

                printf("username=");
                fgets(username, MAX_STRING_LEN, stdin);
                username[strlen(username) - 1] = '\0';

                printf("password=");
                fgets(password, MAX_STRING_LEN, stdin);
                password[strlen(password) - 1] = '\0';
                
                bool is_valid = true;

                // verific corectitudinea credentialelor
                if(strchr(username, ' ') || strchr(password, ' ')){
                    printf("Error: No white spaces allowed for credentials!\n");
                    is_valid = false;
                }

                // creez obiectul JSON cu campurile date user si parola daca sunt corecte 
                if (is_valid) {
                    JSON_Value *value = json_value_init_object();
                    JSON_Object *object = json_value_get_object(value);

                    json_object_set_string(object, "username", username);
                    json_object_set_string(object, "password", password);

                    // introduc in JSON valorile pt a obtine un string
                    char *serialized_string = json_serialize_to_string_pretty(value);
                    json_value_free(value);

                    char *content_type = "application/json";
                    sockfd = open_connection(HOST, 8080, AF_INET, SOCK_STREAM, 0);

                    // creez POST request ul continand credentialele si il trimit la server
                    message = compute_post_request(HOST, REGISTER_URL, content_type, serialized_string, NULL, 0, NULL);
                    // printf("message %s", message);

                    // puts(message);
                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                    // puts(response);

                    // parsez prima linie din response ul primit de la server pentru a gasi status code ul
                    char protocol_v[50], status_text[50];
                    int status_code;

                    sscanf(response, "%s %d %s", protocol_v, &status_code, status_text);

                    // daca user ul a fost creat cu succes
                    if (status_code == 201) {
                        printf("User created successfully!\nUsername: %s\nPassword: %s\n", username, password);
                    } else {
                        printf("Error: The username entered is taken!\n\n");
                    }

                    close_connection(sockfd);
                    free(message);
                }
            }
            
        } else if (strcmp(command, "login") == 0) {
            if (logged_in) {
                printf("User already logged in. In order to login please log out first.\n");
            } else {
                char username[MAX_STRING_LEN], password[MAX_STRING_LEN];

                printf("username=");
                fgets(username, MAX_STRING_LEN, stdin);
                username[strlen(username) - 1] = '\0';

                printf("password=");
                fgets(password, MAX_STRING_LEN, stdin);
                password[strlen(password) - 1] = '\0';
                
                bool is_valid = true;

                if (strchr(username, ' ') || strchr(password, ' ')){
                    printf("Error: No white spaces allowed for credentials!\n");
                    is_valid = false;
                }

                // creez obiectul JSON cu campurile date user si parola, daca sunt corecte
                if (is_valid) {
                    JSON_Value *value = json_value_init_object();
                    JSON_Object *object = json_value_get_object(value);

                    json_object_set_string(object, "username", username);
                    json_object_set_string(object, "password", password);

                    // introduc in JSON valorile pt a obtine un string
                    char *serialized_string = json_serialize_to_string_pretty(value);

                    char *content_type = "application/json";
                    sockfd = open_connection(HOST, 8080, AF_INET, SOCK_STREAM, 0);
                    if (sockfd < 0) {
                        printf("Could not open connection\n");
                    }

                    // creez POST request ul si il trimit la server
                    message = compute_post_request(HOST, LOGIN_URL, content_type, serialized_string, NULL, 0, NULL);
                    // printf("message %s", message);

                    // puts(message);
                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                    // puts(response);
                    
                    // daca login ul a fost realizat cu succes
                    if (strstr(response, "error")) {
                        if (strstr(response, "username")) {
                            printf("Error: The username entered is not registered!\n\n");
                        } else {
                            printf("Error: The password entered is incorrect!\n\n");
                        }
                        
                    } else {
                        logged_in = 1;
                        printf("User logged in!\nUsername: %s\nPassword: %s\n", username, password);
                        
                        // selectez cookie ul din response
                        cookie = strstr(response, "Set-Cookie: ");
                        cookie = strtok(cookie, ";");
                        cookie = strtok(cookie, " ");
                        cookie = strtok(NULL, " ");

                        // session_cookie = cookie;
                    }

                    json_free_serialized_string(serialized_string);
                    json_value_free(value);
                    free(message);
                    free(response);
                    close_connection(sockfd);
                }
            }
            
        } else if (strcmp(command, "logout") == 0) {
            if (logged_in == 0) {
                printf("No user logged in.\n");
            } else {
                sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
                // strcpy(cookie, session_cookie);

                char *cookies[1];
                cookies[0] = cookie;
				// creez GET request ul si il trimit la server
                message = compute_get_request(HOST, LOGOUT_URL, NULL, cookies, 1, NULL);
                send_to_server(sockfd, message);
	
                response = receive_from_server(sockfd);

                if (strstr(response, "error")) {
                    printf("Error: Couldn't disconnect user\n");
                } else {
                    // imi dau logout, deci session cookie ul si token ul se reseteaza
                    logged_in = 0;
                    // session_cookie = NULL;
                    cookie = NULL;
                    in_library = 0;
                    token = NULL;
                    printf("User logged out successfully.\n");
                }

                free(message);
                free(response);
                close_connection(sockfd);
            }
            
        } else if (strcmp(command, "enter_library") == 0) {
            if (!logged_in) {
                printf("User is not logged in.\n\n");
            } else {
                if (in_library) {
                    printf("User already in library.\n\n");
                } else {
                    sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
                    if (sockfd < 0) {
                        printf("Could not open connection\n");
                    }
                    
                    char *cookies[1];
                    cookies[0] = cookie;
                    message = compute_get_request(HOST, ACCESS_URL, NULL, cookies, 1, NULL);
                    // puts(message);
                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                    // puts(response);

                    // daca accesul la library nu a fost permis
                    if (strstr(response, "error")) {
                        puts(response);
                        printf("\n");
                        printf("Error: Access denied!\n");
                    } else {
                        in_library = 1;

                        char *start_token = strstr(response, "token");
                        start_token += 8;

                        // scap de ultima " si de }
                        token = start_token;
                        token[strlen(token) - 2] = '\0';
                        // printf("token: %s\n", token);

                        printf("Library access granted!\n");
                    }
                }

                free(message);
                free(response);
                close_connection(sockfd);
            }
            
        } else if (strcmp(command, "get_books") == 0) {
            if (in_library == 0) {
                printf("You are not in the library.\n\n");
            } else {
                sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
                if (sockfd < 0) {
                    printf("Could not open connection\n");
                }

                char *cookies[1];
                cookies[0] = cookie;
                message = compute_get_request(HOST, BOOKS_URL, NULL, cookies, 1, token);
                // puts(message);
                send_to_server(sockfd, message);

                response = receive_from_server(sockfd);
                // puts(response);

                // verific daca comanda s-a realizat sau nu cu succes
                if (strstr(response, "error")) {
                    printf("Error: Couldn't get books!\n");
                } else {
                    char *json_message = strstr(response, "[");

                    printf("\nBooks in library:\n");

                    JSON_Value *value = json_parse_string(json_message);
                    char *books = json_serialize_to_string_pretty(value);
                    printf("%s\n", books);

                    json_free_serialized_string(books);
                    json_value_free(value);
                }

                close_connection(sockfd);
                free(message);
                free(response);
            }
    
        } else if (strcmp(command, "get_book") == 0) {
            // daca nu am acces la library
            if (in_library == 0) {
                printf("You are not in the library.\n\n");
            } else {
                printf("id=");
                char id[100];
                fgets(id, MAX_STRING_LEN, stdin);
                id[strlen(id) - 1] = '\0';

                int is_valid = 1;
                // verific daca e un numar valid
                for (int i = 0; i < strlen(id); i++) {
                    if (id[i] < '0' || id[i] > '9') {
                        is_valid = 0;
                        printf("Error: Invalid id!\n");
                        break;
                    }
                }

                if (is_valid) {
                    // formez url ul pentru a extrage cartea
                    char get_book_url[100];
                    strcpy(get_book_url, BOOKS_URL);
                    strcat(get_book_url, "/");
                    strcat(get_book_url, id);

                    if (in_library == 0) {
                        printf("You are not in the library.\n\n");
                    } else {
                        sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
                        if (sockfd < 0) {
                            printf("Could not open connection\n");
                        }

                        char *cookies[1];
                        cookies[0] = cookie;
                        message = compute_get_request(HOST, get_book_url, NULL, cookies, 1, token);
                        // puts(message);
                        send_to_server(sockfd, message);

                        response = receive_from_server(sockfd);
                        // puts(response);

                        // verific daca comanda s-a realizat sau nu cu succes
                        if (strstr(response, "error")) {
                            printf("Error: Couldn't find the book with id %s!\n", id);
                        } else {
                            // extrag din json ul din response cartea cu id ul dat
                            char *json_message = strstr(response, "{");

                            printf("\nBook with id %s:\n%s\n", id, json_message);
                        }
                        close_connection(sockfd);
                        free(message);
                        free(response);
                    }
                }
            }

        } else if (strcmp(command, "add_book") == 0) {
            if (in_library == 0) {
                printf("You are not in the library.\n\n");
            } else {
                char title[MAX_STRING_LEN];
                char author[MAX_STRING_LEN];
                char genre[MAX_STRING_LEN];
                char publisher[MAX_STRING_LEN];
                char page_count[MAX_STRING_LEN];

                // citesc campurile cartii cu fgets, pentru a putea citi si spatii (si intreaga linie implicit)
                printf("title=");
                fgets(title, MAX_STRING_LEN, stdin);
                title[strlen(title) - 1] = '\0';

                printf("author=");
                fgets(author, MAX_STRING_LEN, stdin);
                author[strlen(author) - 1] = '\0';

                printf("genre=");
                fgets(genre, MAX_STRING_LEN, stdin);
                genre[strlen(genre) - 1] = '\0';

                printf("publisher=");
                fgets(publisher, MAX_STRING_LEN, stdin);
                publisher[strlen(publisher) - 1] = '\0';

                printf("page_count=");
                fgets(page_count, MAX_STRING_LEN, stdin);
                page_count[strlen(page_count) - 1] = '\0';

                int is_valid = 1;

                // verific corectidutinea campurilor
        
                if (strcmp(title, "") == 0 || strcmp(author, "") == 0 || strcmp(genre, "") == 0 || strcmp(publisher, "") == 0) {
                    is_valid = 0;
                }
               
                // verific daca e nr
                for (int i = 0; i < strlen(page_count); i++) {
                    if (page_count[i] < '0' || page_count[i] > '9') {
                        is_valid = 0;
                        break;
                    }
                }

                if (is_valid == 0) {
                    printf("Error: Invalid book fields!\n");
                } else {
                    // daca campul page_count e valid, formez json ul pt a adauga cartea
                    JSON_Value *value = json_value_init_object();
                    JSON_Object *object = json_value_get_object(value);

                    json_object_set_string(object, "title", title);
                    json_object_set_string(object, "author", author);
                    json_object_set_string(object, "genre", genre);
                    json_object_set_string(object, "publisher", publisher);
                    json_object_set_string(object, "page_count", page_count);

                    char *serialized_string = json_serialize_to_string_pretty(value);
                    
                    sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
                    if (sockfd < 0) {
                        printf("Could not open connection\n");
                    }

                    char *cookies[1];
                    cookies[0] = cookie;
                    message = compute_post_request(HOST, BOOKS_URL, "application/json", serialized_string, cookies, 1, token);
                    // puts(message);
                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                    // puts(response);

                    // verific daca comanda s-a realizat sau nu cu succes
                    if (strstr(response, "error")) {
                        printf("Error: Couldn't add book!\n");
                    } else {
                        printf("Book added successfully!\n");
                    }

                    close_connection(sockfd);
                    free(message);
                    free(response);
                    free(serialized_string);
                }
            }

        } else if (strcmp(command, "delete_book") == 0) {
            // daca nu am acces la library
            if (in_library == 0) {
                printf("You are not in the library.\n\n");
            } else {
                printf("id=");
                char id[100];
                fgets(id, MAX_STRING_LEN, stdin);
                id[strlen(id) - 1] = '\0';

                int is_valid = 1;

				// analog cu add_book
                for (int i = 0; i < strlen(id); i++) {
                    if (id[i] < '0' || id[i] > '9') {
                        is_valid = 0;
                        printf("Error: Invalid id!\n");
                        break;
                    }
                }
                
                if (is_valid) {
                    // formez url ul pentru a extrage cartea
                    char get_book_url[100];
                    strcpy(get_book_url, BOOKS_URL);
                    strcat(get_book_url, "/");
                    strcat(get_book_url, id);

                    if (in_library == 0) {
                        printf("You are not in the library.\n\n");
                    } else {
                        sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
                        if (sockfd < 0) {
                            printf("Could not open connection\n");
                        }

                        char *cookies[1];
                        cookies[0] = cookie;
						// creez DELETE request ul
                        message = compute_delete_request(HOST, get_book_url, NULL, cookies, 1, token);
                        // puts(message);
                        send_to_server(sockfd, message);

                        response = receive_from_server(sockfd);
                        // puts(response);

                        // verific daca comanda s-a realizat sau nu cu succes
                        if (strstr(response, "error")) {
                            printf("Error: Couldn't delete the book with id %s!\n", id);
                        } else {
                            printf("Book deleted successfully!\n");
                            
                            close_connection(sockfd);
                            free(message);
                            free(response);
                        }
                    }
                }
            }
        } else {
            printf("Invalid command!\n");
        }
    }

    return 0;
}

