void MAIN() {
    vec4 mainCol = texture(INPUT, INPUT_UV);
    FRAGCOLOR = vec4(1.0 - mainCol.r, 1.0 - mainCol.g, 1.0 - mainCol.b, mainCol.a);
}
