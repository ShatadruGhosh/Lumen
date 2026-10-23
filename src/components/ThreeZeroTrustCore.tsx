"use client";

import { Canvas, useFrame } from "@react-three/fiber";
import { Float, Sparkles } from "@react-three/drei";
import { useMemo, useRef } from "react";
import * as THREE from "three";

const stageColors = ["#6de8d1", "#9188ff", "#a69cff", "#f1b76e", "#ee88b7"];

function Prism({ stage }: { stage: number }) {
  const core = useRef<THREE.Group>(null);
  const color = stageColors[stage] ?? stageColors[0];

  useFrame((state, delta) => {
    if (!core.current) return;
    const chapterOffset = stage * 0.23;
    core.current.rotation.y = THREE.MathUtils.damp(core.current.rotation.y, state.clock.elapsedTime * 0.12 + chapterOffset, 2.7, delta);
    core.current.rotation.x = THREE.MathUtils.damp(core.current.rotation.x, 0.12 + state.pointer.y * 0.15 + Math.sin(chapterOffset) * 0.13, 3.5, delta);
    core.current.rotation.z = THREE.MathUtils.damp(core.current.rotation.z, state.pointer.x * 0.1 + Math.cos(chapterOffset) * 0.08, 3.5, delta);
    state.camera.position.x = THREE.MathUtils.damp(state.camera.position.x, (stage - 2) * 0.07, 1.6, delta);
    state.camera.position.z = THREE.MathUtils.damp(state.camera.position.z, 5.6 - stage * 0.12, 1.6, delta);
    state.camera.lookAt(0, 0, 0);
  });

  return (
    <group ref={core}>
      <Float speed={1.05} rotationIntensity={0.08} floatIntensity={0.18}>
        <mesh>
          <icosahedronGeometry args={[0.72, 2]} />
          <meshPhysicalMaterial color="#effffa" metalness={0.85} roughness={0.13} clearcoat={1} clearcoatRoughness={0.12} emissive={color} emissiveIntensity={0.32} />
        </mesh>
        <mesh scale={1.16}>
          <icosahedronGeometry args={[0.72, 1]} />
          <meshBasicMaterial color={color} wireframe transparent opacity={0.28} />
        </mesh>
        <mesh rotation={[0.5, 0.35, 0.2]}>
          <torusGeometry args={[1.12, 0.012, 12, 180]} />
          <meshBasicMaterial color={color} transparent opacity={0.88} />
        </mesh>
        <mesh rotation={[1.15, -0.65, 0.8]}>
          <torusGeometry args={[1.5, 0.008, 10, 200]} />
          <meshBasicMaterial color="#bfbcff" transparent opacity={0.48} />
        </mesh>
        <mesh rotation={[-0.82, 0.25, -0.28]}>
          <torusGeometry args={[1.83, 0.006, 10, 200]} />
          <meshBasicMaterial color="#d3d4ec" transparent opacity={0.26} />
        </mesh>
        <mesh position={[1.48, 0.16, 0.12]}>
          <sphereGeometry args={[0.035, 16, 16]} />
          <meshBasicMaterial color="#fff" />
        </mesh>
        <mesh position={[-1.68, -0.36, -0.12]}>
          <sphereGeometry args={[0.027, 16, 16]} />
          <meshBasicMaterial color={color} />
        </mesh>
      </Float>
    </group>
  );
}

export default function ThreeZeroTrustCore({ stage = 0 }: { stage?: number }) {
  const sparkles = useMemo(() => stageColors[stage] ?? stageColors[0], [stage]);

  return (
    <Canvas
      dpr={[1, 1.6]}
      camera={{ position: [0, 0, 5.6], fov: 38 }}
      gl={{ alpha: true, antialias: true, powerPreference: "high-performance" }}
      fallback={<div className="core-canvas-fallback" aria-label="3D visualization unavailable" />}
    >
      <ambientLight intensity={0.5} />
      <pointLight position={[2.5, 2.5, 3]} intensity={17} color="#88fff0" />
      <pointLight position={[-3, -1.5, 2]} intensity={13} color="#8d7cff" />
      <pointLight position={[0, 0, -2]} intensity={9} color={sparkles} />
      <mesh position={[0, 0, -0.5]}>
        <boxGeometry args={[3.9, 2.8, 2.05]} />
        <meshBasicMaterial color={sparkles} wireframe transparent opacity={0.055} />
      </mesh>
      <mesh position={[0, 0, -1.25]}>
        <boxGeometry args={[4.65, 3.35, 2.75]} />
        <meshBasicMaterial color="#a99dff" wireframe transparent opacity={0.035} />
      </mesh>
      <Sparkles count={110} scale={4.8} size={1.5} speed={0.18} opacity={0.48} color={sparkles} />
      <Prism stage={stage} />
    </Canvas>
  );
}
