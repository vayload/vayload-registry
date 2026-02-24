package domain

type DomainError struct {
	Kind    ErrorKind
	Message string
}

type ErrorKind uint

const (
	ErrorKindUnknown ErrorKind = iota
	ErrorKindNotFound
	ErrorKindAlreadyExists
	ErrorKindConflict
	ErrorKindUnauthorized
	ErrorKindForbidden
	ErrorKindValidation
	ErrorKindInternal
	ErrorKindJwt
)

var ErrorKindMap = map[ErrorKind]string{
	ErrorKindUnknown:       "UNKNOWN",
	ErrorKindNotFound:      "NOT_FOUND",
	ErrorKindAlreadyExists: "ALREADY_EXISTS",
	ErrorKindConflict:      "CONFLICT",
	ErrorKindUnauthorized:  "UNAUTHORIZED",
	ErrorKindForbidden:     "FORBIDDEN",
	ErrorKindValidation:    "VALIDATION_ERROR",
	ErrorKindInternal:      "INTERNAL_ERROR",
	ErrorKindJwt:           "JWT_ERROR",
}

func (e DomainError) Error() string {
	return e.Message
}

func NewNotFoundError(message string) error {
	return DomainError{Kind: ErrorKindNotFound, Message: message}
}

func NewAlreadyExistsError(message string) error {
	return DomainError{Kind: ErrorKindAlreadyExists, Message: message}
}

func NewConflictError(message string) error {
	return DomainError{Kind: ErrorKindConflict, Message: message}
}

func NewUnauthorizedError(message string) error {
	return DomainError{Kind: ErrorKindUnauthorized, Message: message}
}

func NewForbiddenError() error {
	return DomainError{Kind: ErrorKindForbidden, Message: "Forbidden"}
}

func NewValidationError(message string) error {
	return DomainError{Kind: ErrorKindValidation, Message: message}
}

func NewInternalError(message string) error {
	return DomainError{Kind: ErrorKindInternal, Message: message}
}

func NewJwtError(message string) error {
	return DomainError{Kind: ErrorKindJwt, Message: message}
}

func IsNotFound(err error) bool {
	if de, ok := err.(DomainError); ok {
		return de.Kind == ErrorKindNotFound
	}
	return false
}

func IsAlreadyExists(err error) bool {
	if de, ok := err.(DomainError); ok {
		return de.Kind == ErrorKindAlreadyExists
	}
	return false
}

func IsConflict(err error) bool {
	if de, ok := err.(DomainError); ok {
		return de.Kind == ErrorKindConflict
	}
	return false
}

func IsUnauthorized(err error) bool {
	if de, ok := err.(DomainError); ok {
		return de.Kind == ErrorKindUnauthorized
	}
	return false
}

func IsForbidden(err error) bool {
	if de, ok := err.(DomainError); ok {
		return de.Kind == ErrorKindForbidden
	}
	return false
}

func IsValidation(err error) bool {
	if de, ok := err.(DomainError); ok {
		return de.Kind == ErrorKindValidation
	}
	return false
}
