package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var secretKey = []byte("library_of_books")

type Book struct {
	BookName        string `json:"book_name"`
	Author          string `json:"author"`
	PublicationYear int    `json:"publication_year"`
}

type User struct {
	UserName string `json:"username"`
	Password string `json:"password"`
	Type     string `json:"type"`
}

var users = []User{
	{"ScaleXMedia", "backend", "admin"},
	{"Karthick", "developer", "regular"},
}

func main() {

	router := gin.Default()

	router.POST("/login", login)
	router.GET("/home", jwtMiddleware(), home)
	router.POST("/addBook", jwtMiddleware(), adminMiddleware(), addBook)
	router.DELETE("/deleteBook", jwtMiddleware(), adminMiddleware(), deleteBook)

	router.Run(":0808")
}

func jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is missing"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Token"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Token"})
		}
		claims := token.Claims.(jwt.MapClaims)
		if claims["type"] != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Admin Permission Required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func login(c *gin.Context) {

	var userInput User

	if err := c.BindJSON(&userInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	for _, user := range users {
		if userInput.UserName == user.UserName && userInput.Password == user.Password {

			// Set expiration time to 12 hours from now
			expirationTime := time.Now().Add(12 * time.Hour)
			token := jwt.NewWithClaims(
				jwt.SigningMethodHS256, jwt.MapClaims{
					"username": user.UserName,
					"type":     user.Type,
					"exp":      expirationTime.Unix(),
				})
			tokenString, err := token.SignedString(secretKey)
			if err != nil {
				fmt.Println(err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to genrate token"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"token": tokenString})
			return
		}
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
}

func home(c *gin.Context) {
	userType := c.GetHeader("type")
	var books []Book
	if userType == "admin" {
		books = append(books, getBooks("regularUser.csv")...)
		books = append(books, getBooks("adminUser.csv")...)
	} else {
		books = append(books, getBooks("regularUser.csv")...)
	}
	c.JSON(http.StatusOK, gin.H{"books": books})
}

func getBooks(filename string) []Book {

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Failed to open file", err)
		return nil
	}
	defer file.Close()
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Failed to read file", err)
		return nil
	}

	var books []Book

	for _, record := range records {
		publicationYear, _ := strconv.Atoi(record[2])
		book := Book{
			BookName:        record[0],
			Author:          record[1],
			PublicationYear: publicationYear,
		}
		books = append(books, book)
	}
	return books
}

func addBook(c *gin.Context) {
	var inputBook Book

	if err := c.ShouldBindJSON(&inputBook); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Data"})
		return
	}

	if err := validateBook(inputBook); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	file, err := os.OpenFile("regularUser.csv", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open file"})
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write the data in new line
	fileInfo, _ := file.Stat()
	if fileInfo.Size() > 0 {
		if _, err := file.WriteString("\n"); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write to file"})
			return
		}
	}

	if err := writer.Write([]string{inputBook.BookName, inputBook.Author, strconv.Itoa(inputBook.PublicationYear)}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write to file"})
		return
	}

	newBook := Book{
		BookName:        inputBook.BookName,
		Author:          inputBook.Author,
		PublicationYear: inputBook.PublicationYear,
	}
	c.JSON(http.StatusOK, gin.H{"message": "Book added successfully", "newBook": newBook})

}

func validateBook(input Book) error {

	if input.BookName == "" {
		return fmt.Errorf("book title cannot be empty")
	}
	if input.Author == "" {
		return fmt.Errorf("author cannot be empty")
	}
	if input.PublicationYear <= 0 {
		return fmt.Errorf("invalid Publication Year ")
	}
	return nil
}

func deleteBook(c *gin.Context) {
	bookName := c.Query("book_name")

	if bookName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Book Name is missing"})
		return
	}

	books := [][]string{}
	fileName := "regularUser.csv"
	file, err := os.Open(fileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open file"})
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	for {
		row, err := reader.Read()
		if err != nil {
			if err != io.EOF {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
				return
			}
			break
		}
		if !strings.EqualFold(row[0], bookName) {
			books = append(books, row)
		}
	}

	file, err = os.Create(fileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open file"})
		return
	}

	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, book := range books {
		if err := writer.Write(book); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write to file"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Book deleted successfully"})

}
