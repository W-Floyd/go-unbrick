// Package dex lists what a Dalvik DEX file declares (its classes, their fields
// and method signatures) and the strings it holds, for recon without a
// decompiler. Parsing is our fork of dextk, which bounds the counts it reads
// by the file's size.
package dex

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/W-Floyd/dextk"
)

// Version is this package's behavior version, for pkg/analysis/cache.
const Version = 1

// open hands dextk a reader that states its size: without one it falls back
// to the header's file_size, which a corrupt file can inflate.
func open(ra io.ReaderAt, size int64) (*dextk.Reader, error) {
	return dextk.Read(io.NewSectionReader(ra, 0, size))
}

// Classes lists every class: its declaration line, then a line per field and
// method, Java-style.
func Classes(ra io.ReaderAt, size int64) (out string, err error) {
	defer guard(&err)
	r, err := open(ra, size)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for it := r.ClassIter(); it.HasNext(); {
		c, err := it.Next()
		if err != nil {
			return b.String(), err
		}
		writeClass(&b, c)
	}
	return b.String(), nil
}

// Strings lists the string table, one per line, quoted so an embedded newline
// or control byte cannot fake a line of its own.
func Strings(ra io.ReaderAt, size int64) (out string, err error) {
	defer guard(&err)
	r, err := open(ra, size)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for it := r.StringIter(); it.HasNext(); {
		s, err := it.Next()
		if err != nil {
			return b.String(), err
		}
		b.WriteString(strconv.Quote(s.Value.String()))
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// guard turns a panic into an error: dextk indexes tables by offsets the file
// states, and carve hands it whatever a container holds.
func guard(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("dex: malformed: %v", r)
	}
}

func writeClass(b *strings.Builder, c dextk.ClassNode) {
	f := c.AccessFlags
	kind := "class"
	switch {
	case f&dextk.AccAnnotation != 0:
		kind, f = "@interface", f&^(dextk.AccInterface|dextk.AccAbstract)
	case f&dextk.AccInterface != 0:
		kind, f = "interface", f&^dextk.AccAbstract
	case f&dextk.AccEnum != 0:
		kind = "enum"
	}
	b.WriteString(modifiers(f&^(dextk.AccInterface|dextk.AccAnnotation|dextk.AccEnum|dextk.AccSuper), false))
	fmt.Fprintf(b, "%s %s", kind, javaName(c.Name.String()))
	if s := c.SuperClass.String(); s != "" && s != "java/lang/Object" {
		fmt.Fprintf(b, " extends %s", javaName(s))
	}
	if len(c.Interfaces) > 0 {
		names := make([]string, len(c.Interfaces))
		for i, n := range c.Interfaces {
			names[i] = javaName(n.String())
		}
		fmt.Fprintf(b, " implements %s", strings.Join(names, ", "))
	}
	if s := c.SourceFile.String(); s != "" {
		fmt.Fprintf(b, "  // %s", s)
	}
	b.WriteString("\n")
	for _, fs := range [][]dextk.FieldNode{c.StaticFields, c.InstanceFields} {
		for _, fd := range fs {
			fmt.Fprintf(b, "  %s%s %s\n", modifiers(fd.AccessFlags, false), typeName(fd.Type), fd.Name.String())
		}
	}
	for _, ms := range [][]dextk.MethodNode{c.DirectMethods, c.VirtualMethods} {
		for _, m := range ms {
			params := make([]string, len(m.Params))
			for i, p := range m.Params {
				params[i] = typeName(p)
			}
			name := m.Name.String()
			ret := typeName(m.ReturnType) + " "
			if name == "<init>" || name == "<clinit>" {
				ret = ""
			}
			fmt.Fprintf(b, "  %s%s%s(%s)\n", modifiers(m.AccessFlags, true), ret, name, strings.Join(params, ", "))
		}
	}
}

// modifiers renders access flags as Java modifiers, each followed by a space.
// Some bits mean different things on a method and a field.
func modifiers(f uint32, method bool) string {
	type bit struct {
		flag uint32
		word string
	}
	bits := []bit{
		{dextk.AccPublic, "public"}, {dextk.AccPrivate, "private"}, {dextk.AccProtected, "protected"},
		{dextk.AccStatic, "static"}, {dextk.AccFinal, "final"}, {dextk.AccAbstract, "abstract"},
		{dextk.AccNative, "native"}, {dextk.AccSynthetic, "synthetic"},
	}
	if method {
		bits = append(bits, bit{dextk.AccDeclaredSynchronized, "synchronized"}, bit{dextk.AccBridge, "bridge"}, bit{dextk.AccVarargs, "varargs"})
	} else {
		bits = append(bits, bit{dextk.AccVolatile, "volatile"}, bit{dextk.AccTransient, "transient"})
	}
	var b strings.Builder
	for _, x := range bits {
		if f&x.flag != 0 {
			b.WriteString(x.word + " ")
		}
	}
	return b.String()
}

var primitives = map[uint8]string{
	'V': "void", 'Z': "boolean", 'B': "byte", 'S': "short", 'C': "char",
	'I': "int", 'J': "long", 'F': "float", 'D': "double",
}

func typeName(d dextk.TypeDescriptor) string {
	base, ok := primitives[d.Type]
	if d.Type == 'L' {
		base, ok = javaName(d.ClassName.String()), true
	}
	if !ok {
		base = d.String()
	}
	return base + strings.Repeat("[]", d.ArrayLength)
}

// javaName turns an internal name ("java/lang/String", or a descriptor
// "Ljava/lang/String;") into a Java one.
func javaName(s string) string {
	if strings.HasPrefix(s, "L") && strings.HasSuffix(s, ";") {
		s = s[1 : len(s)-1]
	}
	return strings.ReplaceAll(s, "/", ".")
}
