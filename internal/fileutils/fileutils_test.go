package fileutils_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd-oidc-brokers/internal/fileutils"
)

func TestFileExists(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		name            string
		fileExists      bool
		parentDirIsFile bool

		expectExists bool
		expectError  bool
	}{
		"Returns true when file exists":                      {fileExists: true, expectExists: true},
		"Returns false when file does not exist":             {fileExists: false, expectExists: false},
		"Returns false when parent directory does not exist": {fileExists: false, expectExists: false},

		"Error when parent directory is a file": {parentDirIsFile: true, expectError: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "file")
			if tc.fileExists {
				err := fileutils.Touch(path)
				require.NoError(t, err, "Touch should not return an error")
			}
			if tc.parentDirIsFile {
				path = filepath.Join(tempDir, "file", "file")
				err := fileutils.Touch(filepath.Join(tempDir, "file"))
				require.NoError(t, err, "Touch should not return an error")
			}

			exists, err := fileutils.FileExists(path)
			if tc.expectError {
				require.Error(t, err, "FileExists should return an error")
			} else {
				require.NoError(t, err, "FileExists should not return an error")
			}
			require.Equal(t, tc.expectExists, exists, "FileExists should return the expected result")
		})
	}
}

func TestIsDirEmpty(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		isEmpty      bool
		isFile       bool
		doesNotExist bool

		expectEmpty bool
		expectError bool
	}{
		"Returns true when directory is empty":      {isEmpty: true, expectEmpty: true},
		"Returns false when directory is not empty": {expectEmpty: false},

		"Error when directory does not exist": {doesNotExist: true, expectError: true},
		"Error when directory is a file":      {isFile: true, expectError: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "dir")

			if !tc.doesNotExist {
				err := os.Mkdir(path, 0o700)
				require.NoError(t, err, "Mkdir should not return an error")
			}

			if !tc.isEmpty && !tc.doesNotExist && !tc.isFile {
				err := fileutils.Touch(filepath.Join(tempDir, "dir", "file"))
				require.NoError(t, err, "Touch should not return an error")
			}
			if tc.isFile {
				path = filepath.Join(tempDir, "file")
				err := fileutils.Touch(path)
				require.NoError(t, err, "Touch should not return an error")
			}

			empty, err := fileutils.IsDirEmpty(path)
			if tc.expectError {
				require.Error(t, err, "IsDirEmpty should return an error")
			} else {
				require.NoError(t, err, "IsDirEmpty should not return an error")
			}
			require.Equal(t, tc.expectEmpty, empty, "IsDirEmpty should return the expected result")
		})
	}
}

func TestTouch(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		name               string
		fileExists         bool
		fileIsDir          bool
		parentDoesNotExist bool

		expectError bool
	}{
		"Creates file when it does not exist":            {fileExists: false},
		"Does not return error when file already exists": {fileExists: true},

		"Returns error when file is a directory":             {fileIsDir: true, expectError: true},
		"Returns error when parent directory does not exist": {parentDoesNotExist: true, expectError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "file")

			if tc.fileExists && !tc.fileIsDir {
				err := fileutils.Touch(path)
				require.NoError(t, err, "Touch should not return an error")
			}

			if tc.fileIsDir {
				path = filepath.Join(tempDir, "dir")
				err := os.Mkdir(path, 0o700)
				require.NoError(t, err, "Mkdir should not return an error")
			}

			if tc.parentDoesNotExist {
				path = filepath.Join(tempDir, "dir", "file")
			}

			err := fileutils.Touch(path)
			if tc.expectError {
				require.Error(t, err, "Touch should return an error")
				return
			}

			require.NoError(t, err, "Touch should not return an error")
		})
	}
}
